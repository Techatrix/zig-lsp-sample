const Server = @This();

const std = @import("std");
const builtin = @import("builtin");
const types = @import("lsp.zig");
const offsets = @import("offsets.zig");
const Transport = @import("Transport.zig");

allocator: std.mem.Allocator,
transport: *Transport,
offset_encoding: offsets.Encoding = .@"utf-16",
status: Status = .uninitialized,
client_capabilities: std.json.Parsed(types.ClientCapabilities),

/// maps document URI's to the document source code
documents: std.StringHashMapUnmanaged([]const u8) = .{},

pub const Error = error{
    OutOfMemory,
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    /// Error code indicating that a server received a notification or
    /// request before the server has received the `initialize` request.
    ServerNotInitialized,
    /// A request failed but it was syntactically correct, e.g the
    /// method name was known and the parameters were valid. The error
    /// message should contain human readable information about why
    /// the request failed.
    ///
    /// @since 3.17.0
    RequestFailed,
    /// The server cancelled the request. This error code should
    /// only be used for requests that explicitly support being
    /// server cancellable.
    ///
    /// @since 3.17.0
    ServerCancelled,
    /// The server detected that the content of a document got
    /// modified outside normal conditions. A server should
    /// NOT send this error code if it detects a content change
    /// in it unprocessed messages. The result even computed
    /// on an older state might still be useful for the client.
    ///
    /// If a client decides that a result is not of any use anymore
    /// the client should cancel the request.
    ContentModified,
    /// The client has canceled a request and a server as detected
    /// the cancel.
    RequestCancelled,
};

pub const Status = enum {
    /// the server has not received a `initialize` request
    uninitialized,
    /// the server has received a `initialize` request and is awaiting the `initialized` notification
    initializing,
    /// the server has been initialized and is ready to received requests
    initialized,
    /// the server has been shutdown and can't handle any more requests
    shutdown,
    /// the server is received a `exit` notification and has been shutdown
    exiting_success,
    /// the server is received a `exit` notification but has not been shutdown
    exiting_failure,
};

fn sendToClientResponse(server: *Server, id: types.RequestId, result: anytype) error{OutOfMemory}![]u8 {
    // TODO validate result type is a possible response
    // TODO validate response is from a client to server request
    // TODO validate result type

    return try server.sendToClientInternal(id, null, null, "result", result);
}

fn sendToClientRequest(server: *Server, id: types.RequestId, method: []const u8, params: anytype) error{OutOfMemory}![]u8 {
    std.debug.assert(isRequestMethod(method));
    // TODO validate method is server to client
    // TODO validate params type

    return try server.sendToClientInternal(id, method, null, "params", params);
}

fn sendToClientNotification(server: *Server, method: []const u8, params: anytype) error{OutOfMemory}![]u8 {
    std.debug.assert(isNotificationMethod(method));
    // TODO validate method is server to client
    // TODO validate params type

    return try server.sendToClientInternal(null, method, null, "params", params);
}

fn sendToClientResponseError(server: *Server, id: types.RequestId, err: ?types.ResponseError) error{OutOfMemory}![]u8 {
    return try server.sendToClientInternal(id, null, err, "", null);
}

fn sendToClientInternal(
    server: *Server,
    maybe_id: ?types.RequestId,
    maybe_method: ?[]const u8,
    maybe_err: ?types.ResponseError,
    extra_name: []const u8,
    extra: anytype,
) error{OutOfMemory}![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(server.allocator);
    var writer = buffer.writer(server.allocator);
    try writer.writeAll(
        \\{"jsonrpc":"2.0"
    );
    if (maybe_id) |id| {
        try writer.writeAll(
            \\,"id":
        );
        try std.json.stringify(id, .{}, writer);
    }
    if (maybe_method) |method| {
        try writer.writeAll(
            \\,"method":
        );
        try std.json.stringify(method, .{}, writer);
    }
    switch (@TypeOf(extra)) {
        void => {},
        ?void => {
            try writer.print(
                \\,"{s}":null
            , .{extra_name});
        },
        else => {
            try writer.print(
                \\,"{s}":
            , .{extra_name});
            try std.json.stringify(extra, .{ .emit_null_optional_fields = false }, writer);
        },
    }
    if (maybe_err) |err| {
        try writer.writeAll(
            \\,"error":
        );
        try std.json.stringify(err, .{}, writer);
    }
    try writer.writeByte('}');

    server.transport.writeJsonMessage(buffer.items) catch |err| {
        std.log.err("failed to write response: {}", .{err});
    };
    return buffer.toOwnedSlice(server.allocator);
}

fn showMessage(
    server: *Server,
    message_type: types.MessageType,
    comptime fmt: []const u8,
    args: anytype,
) void {
    const message = std.fmt.allocPrint(server.allocator, fmt, args) catch return;
    defer server.allocator.free(message);
    switch (message_type) {
        .Error => std.log.err("{s}", .{message}),
        .Warning => std.log.warn("{s}", .{message}),
        .Info => std.log.info("{s}", .{message}),
        .Log => std.log.debug("{s}", .{message}),
    }
    switch (server.status) {
        .initializing,
        .initialized,
        => {},
        .uninitialized,
        .shutdown,
        .exiting_success,
        .exiting_failure,
        => return,
    }
    if (server.sendToClientNotification("window/showMessage", types.ShowMessageParams{
        .type = message_type,
        .message = message,
    })) |json_message| {
        server.allocator.free(json_message);
    } else |err| {
        std.log.warn("failed to show message: {}", .{err});
    }
}

fn initializeHandler(server: *Server, _: std.mem.Allocator, request: types.InitializeParams) Error!types.InitializeResult {
    if (request.clientInfo) |clientInfo| {
        std.log.info("client is '{s}-{s}'", .{ clientInfo.name, clientInfo.version orelse "<no version>" });
    }

    // I know...
    const capabilities_string = try std.json.stringifyAlloc(server.allocator, request.capabilities, .{});
    defer server.allocator.free(capabilities_string);
    server.client_capabilities.deinit();
    server.client_capabilities = std.json.parseFromSlice(
        types.ClientCapabilities,
        server.allocator,
        capabilities_string,
        .{ .allocate = .alloc_always },
    ) catch return error.InternalError;

    server.status = .initializing;

    return .{
        .serverInfo = .{
            .name = "zig-lsp-sample",
            .version = null,
        },
        .capabilities = .{
            .positionEncoding = switch (server.offset_encoding) {
                .@"utf-8" => .@"utf-8",
                .@"utf-16" => .@"utf-16",
                .@"utf-32" => .@"utf-32",
            },
            .textDocumentSync = .{
                .TextDocumentSyncOptions = .{
                    .openClose = true,
                    .change = .Full,
                    .save = .{ .bool = true },
                },
            },
            .completionProvider = .{
                .triggerCharacters = &[_][]const u8{ ".", ":", "@", "]", "/" },
            },
            .hoverProvider = .{ .bool = true },
            .definitionProvider = .{ .bool = true },
            .referencesProvider = .{ .bool = true },
            .documentFormattingProvider = .{ .bool = true },
            .semanticTokensProvider = .{
                .SemanticTokensOptions = .{
                    .full = .{ .bool = true },
                    .legend = .{
                        .tokenTypes = std.meta.fieldNames(types.SemanticTokenTypes),
                        .tokenModifiers = std.meta.fieldNames(types.SemanticTokenModifiers),
                    },
                },
            },
            .inlayHintProvider = .{ .bool = true },
        },
    };
}

fn initializedHandler(server: *Server, _: std.mem.Allocator, notification: types.InitializedParams) Error!void {
    _ = notification;

    if (server.status != .initializing) {
        std.log.warn("received a initialized notification but the server has not send a initialize request!", .{});
    }

    server.status = .initialized;
}

fn shutdownHandler(server: *Server, _: std.mem.Allocator, _: void) Error!?void {
    defer server.status = .shutdown;
    if (server.status != .initialized) return error.InvalidRequest; // received a shutdown request but the server is not initialized!
}

fn exitHandler(server: *Server, _: std.mem.Allocator, _: void) Error!void {
    server.status = switch (server.status) {
        .initialized => .exiting_failure,
        .shutdown => .exiting_success,
        else => unreachable,
    };
}

fn openDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidOpenTextDocumentParams) Error!void {
    const new_text = try server.allocator.dupe(u8, notification.textDocument.text); // We informed the client that we only do full document syncs
    errdefer server.allocator.free(new_text);

    const gop = try server.documents.getOrPut(server.allocator, notification.textDocument.uri);
    if (gop.found_existing) {
        server.allocator.free(gop.value_ptr.*); // free old text even though this shoudnt be necessary
    } else {
        errdefer std.debug.assert(server.documents.remove(notification.textDocument.uri));
        gop.key_ptr.* = try server.allocator.dupe(u8, notification.textDocument.uri);
    }
    gop.value_ptr.* = new_text;
}

fn changeDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidChangeTextDocumentParams) Error!void {
    if (notification.contentChanges.len == 0) return;
    const new_text = try server.allocator.dupe(u8, notification.contentChanges[notification.contentChanges.len - 1].literal_1.text); // We informed the client that we only do full document syncs
    errdefer server.allocator.free(new_text);

    const gop = try server.documents.getOrPut(server.allocator, notification.textDocument.uri);
    if (gop.found_existing) {
        server.allocator.free(gop.value_ptr.*); // free old text even though this shoudnt be necessary
    } else {
        errdefer std.debug.assert(server.documents.remove(notification.textDocument.uri));
        gop.key_ptr.* = try server.allocator.dupe(u8, notification.textDocument.uri);
    }
    gop.value_ptr.* = new_text;
}

fn saveDocumentHandler(server: *Server, arena: std.mem.Allocator, notification: types.DidSaveTextDocumentParams) Error!void {
    _ = server;
    _ = arena;
    _ = notification;
}

fn closeDocumentHandler(server: *Server, _: std.mem.Allocator, notification: types.DidCloseTextDocumentParams) error{}!void {
    const kv = server.documents.fetchRemove(notification.textDocument.uri) orelse return;
    server.allocator.free(kv.key);
    server.allocator.free(kv.value);
}

fn completionHandler(server: *Server, arena: std.mem.Allocator, request: types.CompletionParams) Error!ResultType("textDocument/completion") {
    _ = server;
    _ = request;
    var completions: std.ArrayListUnmanaged(types.CompletionItem) = .{};

    try completions.append(arena, types.CompletionItem{
        .label = "ziggy",
        .kind = .Text,
        .documentation = .{ .string = "Is a Zig-flavored data format" },
    });

    try completions.append(arena, types.CompletionItem{
        .label = "zls",
        .kind = .Function,
        .documentation = .{ .string = "is a Zig LSP" },
    });

    return .{
        .CompletionList = types.CompletionList{
            .isIncomplete = false,
            .items = completions.items,
        },
    };
}

fn gotoDefinitionHandler(server: *Server, arena: std.mem.Allocator, request: types.DefinitionParams) Error!ResultType("textDocument/definition") {
    _ = server;
    _ = arena;
    _ = request;
    return null;
}

fn hoverHandler(server: *Server, arena: std.mem.Allocator, request: types.HoverParams) Error!?types.Hover {
    _ = arena;

    const text = server.documents.get(request.textDocument.uri) orelse return null;
    const line = offsets.lineSliceAtPosition(text, request.position, server.offset_encoding);

    return types.Hover{
        .contents = .{
            .MarkupContent = .{
                .kind = .plaintext,
                .value = line,
            },
        },
    };
}

fn referencesHandler(server: *Server, arena: std.mem.Allocator, request: types.ReferenceParams) Error!?[]types.Location {
    _ = server;
    _ = arena;
    _ = request;
    return null;
}

fn formattingHandler(server: *Server, arena: std.mem.Allocator, request: types.DocumentFormattingParams) Error!?[]types.TextEdit {
    _ = server;
    _ = arena;
    _ = request;
    return null;
}

fn semanticTokensFullHandler(server: *Server, arena: std.mem.Allocator, request: types.SemanticTokensParams) Error!?types.SemanticTokens {
    _ = server;
    _ = arena;
    _ = request;
    return null;
}

fn inlayHintHandler(server: *Server, arena: std.mem.Allocator, request: types.InlayHintParams) Error!?[]types.InlayHint {
    _ = server;
    _ = arena;
    _ = request;
    return null;
}

/// workaround for https://github.com/ziglang/zig/issues/16392
/// ```zig
/// union(enum) {
///    request: Request,
///    notification: Notification,
///    response: Response,
/// }
/// ```zig
pub const Message = struct {
    tag: enum(u32) {
        request,
        notification,
        response,
    },
    request: ?Request = null,
    notification: ?Notification = null,
    response: ?Response = null,

    pub const Request = struct {
        id: types.RequestId,
        params: Params,

        pub const Params = union(enum) {
            initialize: types.InitializeParams,
            shutdown: void,
            @"textDocument/completion": types.CompletionParams,
            @"textDocument/hover": types.HoverParams,
            @"textDocument/definition": types.DefinitionParams,
            @"textDocument/references": types.ReferenceParams,
            @"textDocument/formatting": types.DocumentFormattingParams,
            @"textDocument/semanticTokens/full": types.SemanticTokensParams,
            @"textDocument/inlayHint": types.InlayHintParams,
            // Not every request is included here so that the we reduce the amount of parsing code we have generate
            unknown: []const u8,
        };
    };

    pub const Notification = union(enum) {
        initialized: types.InitializedParams,
        exit: void,
        @"textDocument/didOpen": types.DidOpenTextDocumentParams,
        @"textDocument/didChange": types.DidChangeTextDocumentParams,
        @"textDocument/didSave": types.DidSaveTextDocumentParams,
        @"textDocument/didClose": types.DidCloseTextDocumentParams,
        // Not every notification is included here so that the we reduce the amount of parsing code we have generate
        unknown: []const u8,
    };

    pub const Response = struct {
        id: types.RequestId,
        data: Data,

        pub const Data = union(enum) {
            result: types.LSPAny,
            @"error": types.ResponseError,
        };
    };

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!Message {
        const json_value = try std.json.parseFromTokenSourceLeaky(std.json.Value, allocator, source, options);
        return try jsonParseFromValue(allocator, json_value, options);
    }

    pub fn jsonParseFromValue(
        allocator: std.mem.Allocator,
        source: std.json.Value,
        options: std.json.ParseOptions,
    ) !Message {
        if (source != .object) return error.UnexpectedToken;
        const object = source.object;

        @setEvalBranchQuota(10_000);
        if (object.get("id")) |id_obj| {
            const msg_id = try std.json.parseFromValueLeaky(types.RequestId, allocator, id_obj, options);

            if (object.get("method")) |method_obj| {
                const msg_method = try std.json.parseFromValueLeaky([]const u8, allocator, method_obj, options);

                const msg_params = object.get("params") orelse .null;

                const fields = @typeInfo(Request.Params).Union.fields;

                inline for (fields) |field| {
                    if (std.mem.eql(u8, msg_method, field.name)) {
                        const params = if (field.type == void)
                            void{}
                        else
                            try std.json.parseFromValueLeaky(field.type, allocator, msg_params, options);

                        return .{
                            .tag = .request,
                            .request = .{
                                .id = msg_id,
                                .params = @unionInit(Request.Params, field.name, params),
                            },
                        };
                    }
                }
                return .{
                    .tag = .request,
                    .request = .{
                        .id = msg_id,
                        .params = .{ .unknown = msg_method },
                    },
                };
            } else {
                const result = object.get("result") orelse .null;
                const error_obj = object.get("error") orelse .null;

                const err = try std.json.parseFromValueLeaky(?types.ResponseError, allocator, error_obj, options);

                if (result != .null and err != null) return error.UnexpectedToken;

                if (err) |e| {
                    return .{
                        .tag = .response,
                        .response = .{
                            .id = msg_id,
                            .data = .{ .@"error" = e },
                        },
                    };
                } else {
                    return .{
                        .tag = .response,
                        .response = .{
                            .id = msg_id,
                            .data = .{ .result = result },
                        },
                    };
                }
            }
        } else {
            const method_obj = object.get("method") orelse return error.UnexpectedToken;
            const msg_method = try std.json.parseFromValueLeaky([]const u8, allocator, method_obj, options);

            const msg_params = object.get("params") orelse .null;

            const fields = @typeInfo(Notification).Union.fields;

            inline for (fields) |field| {
                if (std.mem.eql(u8, msg_method, field.name)) {
                    const params = if (field.type == void)
                        void{}
                    else
                        try std.json.parseFromValueLeaky(field.type, allocator, msg_params, options);

                    return .{
                        .tag = .notification,
                        .notification = @unionInit(Notification, field.name, params),
                    };
                }
            }
            return .{
                .tag = .notification,
                .notification = .{ .unknown = msg_method },
            };
        }
    }

    pub fn format(message: Message, comptime fmt_str: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, message);
        switch (message.tag) {
            .request => try writer.print("request-{}-{s}", .{ message.request.?.id, switch (message.request.?.params) {
                .unknown => |method| method,
                else => @tagName(message.request.?.params),
            } }),
            .notification => try writer.print("notification-{s}", .{switch (message.notification.?) {
                .unknown => |method| method,
                else => @tagName(message.notification.?),
            }}),
            .response => try writer.print("response-{}", .{message.response.?.id}),
        }
    }
};

pub fn create(allocator: std.mem.Allocator, transport: *Transport) !*Server {
    const server = try allocator.create(Server);
    errdefer server.destroy();
    server.* = Server{
        .allocator = allocator,
        .transport = transport,
        .client_capabilities = try std.json.parseFromSlice(types.ClientCapabilities, allocator, "{}", .{}),
    };

    return server;
}

pub fn destroy(server: *Server) void {
    server.client_capabilities.deinit();
    server.allocator.destroy(server);
}

pub fn keepRunning(server: Server) bool {
    switch (server.status) {
        .exiting_success, .exiting_failure => return false,
        else => return true,
    }
}

pub fn loop(server: *Server) !void {
    while (server.keepRunning()) {
        // `json_message` is the message that is send from the client to the server (request or notification or response)
        const json_message = try server.transport.readJsonMessage(server.allocator);
        defer server.allocator.free(json_message);

        // `send_message` is the message that is send from the server to the client (response)
        const send_message = try server.sendJsonMessageSync(json_message) orelse continue; // no response message on notifications
        server.allocator.free(send_message);
    }
}

pub fn sendJsonMessageSync(server: *Server, json_message: []const u8) Error!?[]u8 {
    const parsed_message = std.json.parseFromSlice(
        Message,
        server.allocator,
        json_message,
        .{ .ignore_unknown_fields = true, .max_value_len = null },
    ) catch return error.ParseError;
    defer parsed_message.deinit();
    return try server.processMessage(parsed_message.value);
}

pub fn sendRequestSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: ParamsType(method)) Error!ResultType(method) {
    comptime std.debug.assert(isRequestMethod(method));
    const RequestMethods = std.meta.Tag(Message.Request.Params);

    return switch (comptime std.meta.stringToEnum(RequestMethods, method).?) {
        .initialize => try server.initializeHandler(arena, params),
        .shutdown => try server.shutdownHandler(arena, params),
        .@"textDocument/completion" => try server.completionHandler(arena, params),
        .@"textDocument/hover" => try server.hoverHandler(arena, params),
        .@"textDocument/definition" => try server.gotoDefinitionHandler(arena, params),
        .@"textDocument/references" => try server.referencesHandler(arena, params),
        .@"textDocument/formatting" => try server.formattingHandler(arena, params),
        .@"textDocument/semanticTokens/full" => try server.semanticTokensFullHandler(arena, params),
        .@"textDocument/inlayHint" => try server.inlayHintHandler(arena, params),
        .unknown => return null,
    };
}

pub fn sendNotificationSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: ParamsType(method)) Error!void {
    comptime std.debug.assert(isNotificationMethod(method));
    const NotificationMethods = std.meta.Tag(Message.Notification);

    return switch (comptime std.meta.stringToEnum(NotificationMethods, method).?) {
        .initialized => try server.initializedHandler(arena, params),
        .exit => try server.exitHandler(arena, params),
        .@"textDocument/didOpen" => try server.openDocumentHandler(arena, params),
        .@"textDocument/didChange" => try server.changeDocumentHandler(arena, params),
        .@"textDocument/didSave" => try server.saveDocumentHandler(arena, params),
        .@"textDocument/didClose" => try server.closeDocumentHandler(arena, params),
        .unknown => return,
    };
}

pub fn sendMessageSync(server: *Server, arena: std.mem.Allocator, comptime method: []const u8, params: ParamsType(method)) Error!ResultType(method) {
    comptime std.debug.assert(isRequestMethod(method) or isNotificationMethod(method));

    if (comptime isRequestMethod(method)) {
        return try server.sendRequestSync(arena, method, params);
    } else if (comptime isNotificationMethod(method)) {
        return try server.sendNotificationSync(arena, method, params);
    } else unreachable;
}

fn processMessage(server: *Server, message: Message) Error!?[]u8 {
    var timer = std.time.Timer.start() catch null;
    defer if (timer) |*t| {
        const total_time = @divFloor(t.read(), std.time.ns_per_ms);
        std.log.debug("Took {d}ms to process {}", .{ total_time, message });
    };

    try server.validateMessage(message);

    // Set up an ArenaAllocator that can be used any allocations that are only needed while handling a single request.
    var arena_allocator = std.heap.ArenaAllocator.init(server.allocator);
    defer arena_allocator.deinit();

    @setEvalBranchQuota(5_000);
    switch (message.tag) {
        .request => switch (message.request.?.params) {
            inline else => |params, method| {
                const result = try server.sendRequestSync(arena_allocator.allocator(), @tagName(method), params);
                return try server.sendToClientResponse(message.request.?.id, result);
            },
            .unknown => return try server.sendToClientResponse(message.request.?.id, null),
        },
        .notification => switch (message.notification.?) {
            inline else => |params, method| {
                try server.sendNotificationSync(arena_allocator.allocator(), @tagName(method), params);
            },
            .unknown => {},
        },
        .response => try server.handleResponse(message.response.?),
    }
    return null;
}

fn validateMessage(server: *const Server, message: Message) Error!void {
    const method = switch (message.tag) {
        .request => switch (message.request.?.params) {
            .unknown => |method| blk: {
                if (!isRequestMethod(method)) return error.MethodNotFound;
                break :blk method;
            },
            else => @tagName(message.request.?.params),
        },
        .notification => switch (message.notification.?) {
            .unknown => |method| blk: {
                if (!isNotificationMethod(method)) return error.MethodNotFound;
                break :blk method;
            },
            else => @tagName(message.notification.?),
        },
        .response => return, // validation happens in `handleResponse`
    };

    switch (server.status) {
        .uninitialized => blk: {
            if (std.mem.eql(u8, method, "initialize")) break :blk;
            if (std.mem.eql(u8, method, "exit")) break :blk;

            return error.ServerNotInitialized; // server received a request before being initialized!
        },
        .initializing => blk: {
            if (std.mem.eql(u8, method, "initialized")) break :blk;
            if (std.mem.eql(u8, method, "$/progress")) break :blk;

            return error.InvalidRequest; // server received a request during initialization!
        },
        .initialized => {},
        .shutdown => blk: {
            if (std.mem.eql(u8, method, "exit")) break :blk;

            return error.InvalidRequest; // server received a request after shutdown!
        },
        .exiting_success,
        .exiting_failure,
        => unreachable,
    }
}

/// Handle a reponse that we have received from the client.
/// Doesn't usually happen unless we explicitly send a request to the client.
fn handleResponse(server: *Server, response: Message.Response) Error!void {
    _ = server;

    const id: []const u8 = switch (response.id) {
        .string => |id| id,
        .integer => |id| {
            std.log.warn("received response from client with id '{d}' that has no handler!", .{id});
            return;
        },
    };

    if (response.data == .@"error") {
        const err = response.data.@"error";
        std.log.err("Error response for '{s}': {}, {s}", .{ id, err.code, err.message });
        return;
    }

    std.log.warn("received response from client with id '{s}' that has no handler!", .{id});
}

//
// LSP helper functions
//

pub fn ResultType(comptime method: []const u8) type {
    if (getRequestMetadata(method)) |meta| return meta.Result;
    if (isNotificationMethod(method)) return void;
    @compileError("unknown method '" ++ method ++ "'");
}

pub fn ParamsType(comptime method: []const u8) type {
    if (getRequestMetadata(method)) |meta| return meta.Params orelse void;
    if (getNotificationMetadata(method)) |meta| return meta.Params orelse void;
    @compileError("unknown method '" ++ method ++ "'");
}

fn getRequestMetadata(comptime method: []const u8) ?types.RequestMetadata {
    for (types.request_metadata) |meta| {
        if (std.mem.eql(u8, method, meta.method)) {
            return meta;
        }
    }
    return null;
}

fn getNotificationMetadata(comptime method: []const u8) ?types.NotificationMetadata {
    for (types.notification_metadata) |meta| {
        if (std.mem.eql(u8, method, meta.method)) {
            return meta;
        }
    }
    return null;
}

const RequestMethodSet = blk: {
    @setEvalBranchQuota(5000);
    var kvs_list: [types.request_metadata.len]struct { []const u8 } = undefined;
    for (types.request_metadata, &kvs_list) |meta, *kv| {
        kv.* = .{meta.method};
    }
    break :blk std.ComptimeStringMap(void, &kvs_list);
};

const NotificationMethodSet = blk: {
    @setEvalBranchQuota(5000);
    var kvs_list: [types.notification_metadata.len]struct { []const u8 } = undefined;
    for (types.notification_metadata, &kvs_list) |meta, *kv| {
        kv.* = .{meta.method};
    }
    break :blk std.ComptimeStringMap(void, &kvs_list);
};

/// return true if there is a request with the given method name
pub fn isRequestMethod(method: []const u8) bool {
    return RequestMethodSet.has(method);
}

/// return true if there is a notification with the given method name
pub fn isNotificationMethod(method: []const u8) bool {
    return NotificationMethodSet.has(method);
}
