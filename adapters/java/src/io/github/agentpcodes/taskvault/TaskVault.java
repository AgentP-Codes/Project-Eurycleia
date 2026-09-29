// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0
package io.github.agentpcodes.taskvault;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * taskvault for Java agents. No dependencies: the Java 17+ standard library only. One file: copy it in.
 *
 * <p>A thin client for {@code taskvault api} running on the same computer. Every check, placeholder, pseudonym,
 * audit entry and block happens in taskvault itself; this class only carries requests and runs the actions
 * (email, refunds, ...) that taskvault has approved, using handlers you register.
 */
public final class TaskVault {
    private static final Set<String> LOCAL = Set.of("127.0.0.1", "localhost");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_REPLY = 16 * 1024 * 1024;

    private final String base;
    private final String token;
    private final HttpClient http;
    private final Duration timeout;
    private final Map<String, ActionHandler> handlers = new ConcurrentHashMap<>();

    /** Runs an approved action. {@code args} holds REAL values: don't log them or give them to the model. */
    @FunctionalInterface
    public interface ActionHandler {
        Object run(Map<String, Object> args) throws Exception;
    }

    /** taskvault couldn't be reached or rejected the request (a blocked action is not an exception). */
    public static final class TaskVaultException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;

        public TaskVaultException(String message, int status) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    /** Result of a tool call, read or action. Check {@link #blocked()}: a blocked call is not an error. */
    public record Result(boolean ok, boolean blocked, String reason, String error, Object value) {
        /** The text to hand back to the model. */
        public String forModel() {
            if (ok) return value instanceof String s ? s : Json.write(value);
            return blocked ? "Blocked by taskvault: " + reason : "Error: " + error;
        }
    }

    /** A tool the model may call; {@code inputSchema} is JSON Schema. */
    public record ToolSpec(String name, String description, Map<String, Object> inputSchema) {}

    public TaskVault(String address, String token) {
        this(address, token, Duration.ofMinutes(10));
    }

    public TaskVault(String address, String token, Duration timeout) {
        URI u;
        try {
            u = URI.create(address);
        } catch (IllegalArgumentException e) {
            throw new TaskVaultException("bad taskvault address", 0);
        }
        if (!"http".equals(u.getScheme()) || u.getHost() == null || !LOCAL.contains(u.getHost())) {
            throw new TaskVaultException("taskvault api only runs on this computer (http://127.0.0.1)", 0);
        }
        if (token == null || token.isEmpty()) throw new TaskVaultException("missing token", 0);
        // the server listens on IPv4 only: never let "localhost" go to ::1, where another program could listen
        this.base = "http://127.0.0.1" + (u.getPort() > 0 ? ":" + u.getPort() : "");
        this.token = token;
        this.timeout = timeout;
        this.http = HttpClient.newBuilder()
                .proxy(HttpClient.Builder.NO_PROXY)              // this computer: never through a proxy
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** Connect using TASKVAULT_URL and TASKVAULT_TOKEN, or the file {@code taskvault api} writes. */
    public static TaskVault connect() {
        String url = System.getenv("TASKVAULT_URL"), tok = System.getenv("TASKVAULT_TOKEN");
        if (url == null || tok == null || url.isEmpty() || tok.isEmpty()) {
            String home = System.getenv("TASKVAULT_HOME");
            Path file = home != null ? Path.of(home, "api.json") : Path.of(System.getProperty("user.home"), ".taskvault", "api.json");
            try {
                Map<String, Object> info = Json.object(Files.readString(file));
                url = (String) info.get("url");
                tok = (String) info.get("token");
            } catch (IOException | RuntimeException e) {
                throw new TaskVaultException(
                        "can't find a running taskvault: start `taskvault api`, or set TASKVAULT_URL and TASKVAULT_TOKEN", 0);
            }
        }
        TaskVault tv = new TaskVault(url, tok);
        tv.request("GET", "/v1/health", null);
        return tv;
    }

    @Override
    public String toString() {
        return "TaskVault(" + base + ")";                         // never the token
    }

    /** Register the code that runs an action once taskvault has approved it. */
    public TaskVault onAction(String sink, ActionHandler handler) {
        handlers.put(sink, handler);
        return this;
    }

    /** Start a task. {@code trusted} must come from your app (e.g. the logged-in customer), never the model. */
    @SuppressWarnings("unchecked")
    public Task startTask(String template, Map<String, ?> trusted) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", template);
        body.put("trusted", trusted == null ? Map.of() : trusted);
        Map<String, Object> out = request("POST", "/v1/tasks", body);
        List<ToolSpec> tools = new ArrayList<>();
        for (Object o : (List<Object>) out.getOrDefault("tools", List.of())) {
            Map<String, Object> t = (Map<String, Object>) o;
            tools.add(new ToolSpec((String) t.get("name"), (String) t.get("description"),
                    (Map<String, Object>) t.get("input_schema")));
        }
        return new Task(this, (String) out.get("task"), Collections.unmodifiableList(tools));
    }

    private byte[] mac(String... parts) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return m.doFinal(String.join("\n", parts).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // Every request is signed with the token (which itself never goes over the connection), and a reply is only
    // trusted if it carries the server's signature, so another program on the port can't pose as taskvault.
    private Map<String, Object> request(String method, String path, Object body) {
        byte[] payload = body == null ? new byte[0] : Json.write(body).getBytes(StandardCharsets.UTF_8);
        byte[] nb = new byte[16];
        RANDOM.nextBytes(nb);
        String nonce = HexFormat.of().formatHex(nb), ts = Long.toString(System.currentTimeMillis() / 1000);
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(timeout)
                .header("content-type", "application/json")
                .header("x-taskvault-time", ts).header("x-taskvault-nonce", nonce)
                .header("x-taskvault-auth", HexFormat.of().formatHex(mac("TV1", method, path, ts, nonce, sha256(payload))));
        b = body == null ? b.method(method, HttpRequest.BodyPublishers.noBody())
                : b.method(method, HttpRequest.BodyPublishers.ofByteArray(payload));
        HttpResponse<byte[]> resp;
        try {
            resp = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new TaskVaultException("can't reach taskvault at " + base + " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")", 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TaskVaultException("interrupted", 0);
        }
        if (resp.body().length > MAX_REPLY) throw new TaskVaultException("reply too large", 0);
        byte[] got;
        try {
            got = HexFormat.of().parseHex(resp.headers().firstValue("x-taskvault-auth").orElse(""));
        } catch (IllegalArgumentException e) {
            got = new byte[0];
        }
        byte[] want = mac("TV1-RESPONSE", nonce, Integer.toString(resp.statusCode()), sha256(resp.body()));
        if (!MessageDigest.isEqual(got, want)) {
            throw new TaskVaultException(resp.statusCode() == 401
                    ? "taskvault refused the request: wrong token, or this computer's clock is off by more than 2 minutes"
                    : "the server at " + base + " couldn't prove it is taskvault; not trusting its reply", resp.statusCode());
        }
        Map<String, Object> data;
        try {
            data = Json.object(new String(resp.body(), StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new TaskVaultException("unexpected reply from taskvault", resp.statusCode());
        }
        if (resp.statusCode() != 200) {
            Object err = data.get("error");
            throw new TaskVaultException(err != null ? err.toString() : "taskvault replied " + resp.statusCode(),
                    resp.statusCode());
        }
        return data;
    }

    @SuppressWarnings("unchecked")
    private Result run(String path, Map<String, Object> body) {
        Map<String, Object> out = request("POST", path, body);
        while ("execute".equals(out.get("status"))) {
            String sink = (String) out.get("sink");
            ActionHandler h = handlers.get(sink);
            Map<String, Object> reply = new LinkedHashMap<>();
            if (h == null) {
                reply.put("error", "no handler registered for " + sink + " (use onAction)");
            } else {
                try {
                    Object result = h.run((Map<String, Object>) out.getOrDefault("args", Map.of()));
                    Json.write(result);                     // fails here (not mid-request) if it can't be sent
                    reply.put("result", result);
                } catch (Exception | StackOverflowError e) {
                    reply.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
            out = request("POST", "/v1/exec/" + enc((String) out.get("exec")), reply);
        }
        String status = String.valueOf(out.get("status"));
        return switch (status) {
            case "ok" -> new Result(true, false, null, null, out.get("result"));
            case "blocked" -> new Result(false, true, String.valueOf(out.get("reason")), null, null);
            default -> new Result(false, false, null, String.valueOf(out.getOrDefault("message", "error")), null);
        };
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    /** One running task. */
    public static final class Task {
        private final TaskVault tv;
        private final String id;
        private final List<ToolSpec> tools;

        private Task(TaskVault tv, String id, List<ToolSpec> tools) {
            this.tv = tv;
            this.id = id;
            this.tools = tools;
        }

        public List<ToolSpec> tools() {
            return tools;
        }

        private String path(String op) {
            return "/v1/tasks/" + enc(id) + "/" + op;
        }

        /** Call a tool the model asked for. */
        public Result call(String name, Map<String, ?> args) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("name", name);
            body.put("arguments", args == null ? Map.of() : args);
            return tv.run(path("call"), body);
        }

        /** {@link #call}, as the text to hand back to the model. */
        public String callForModel(String name, Map<String, ?> args) {
            return call(name, args).forModel();
        }

        /** Read from a source directly (code-first apps). key and fields may be null. */
        public Result read(String source, Object key, List<String> fields) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("source", source);
            body.put("key", key);
            if (fields != null) body.put("fields", fields);
            return tv.run(path("read"), body);
        }

        /** Ask for an action directly (code-first apps). Runs your onAction handler if approved. */
        public Result act(String sink, Map<String, ?> args) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("sink", sink);
            body.put("args", args == null ? Map.of() : args);
            return tv.run(path("act"), body);
        }

        public void end() {
            tv.request("POST", path("end"), Map.of());
        }

        /** OpenAI chat-completions {@code tools} (also Ollama and most OpenAI-compatible servers), as JSON. */
        public String openAIToolsJson() {
            List<Object> out = new ArrayList<>();
            for (ToolSpec t : tools) {
                Map<String, Object> fn = new LinkedHashMap<>();
                fn.put("name", t.name());
                fn.put("description", t.description());
                fn.put("parameters", t.inputSchema());
                out.add(Map.of("type", "function", "function", fn));
            }
            return Json.write(out);
        }

        /** Anthropic Messages API {@code tools}, as JSON. */
        public String anthropicToolsJson() {
            List<Object> out = new ArrayList<>();
            for (ToolSpec t : tools) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", t.name());
                m.put("description", t.description());
                m.put("input_schema", t.inputSchema());
                out.add(m);
            }
            return Json.write(out);
        }

        @Override
        public String toString() {
            return "Task";
        }
    }

    /** Minimal, strict JSON (RFC 8259) so this file needs no library. Objects keep their key order. */
    public static final class Json {
        private static final int MAX_DEPTH = 200;
        private final String s;
        private int i;

        private Json(String s) {
            this.s = s;
        }

        @SuppressWarnings("unchecked")
        public static Map<String, Object> object(String text) {
            Object v = parse(text);
            if (!(v instanceof Map)) throw new IllegalArgumentException("expected a JSON object");
            return (Map<String, Object>) v;
        }

        public static Object parse(String text) {
            Json p = new Json(text);
            p.ws();
            Object v = p.value(0);
            p.ws();
            if (p.i != text.length()) throw p.err("trailing characters");
            return v;
        }

        private IllegalArgumentException err(String what) {
            return new IllegalArgumentException("bad JSON at " + i + ": " + what);
        }

        private void ws() {
            while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++;
        }

        private Object value(int depth) {
            if (depth > MAX_DEPTH) throw err("nested too deeply");
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i);
            switch (c) {
                case '{': return obj(depth);
                case '[': return arr(depth);
                case '"': return str();
                case 't': return lit("true", Boolean.TRUE);
                case 'f': return lit("false", Boolean.FALSE);
                case 'n': return lit("null", null);
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return num();
                    throw err("unexpected character");
            }
        }

        private Object lit(String word, Object v) {
            if (!s.startsWith(word, i)) throw err("unexpected word");
            i += word.length();
            return v;
        }

        private Map<String, Object> obj(int depth) {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') throw err("expected a key");
                String k = str();
                ws();
                if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
                i++;
                ws();
                m.put(k, value(depth + 1));
                ws();
                if (i >= s.length()) throw err("unexpected end");
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw err("expected ',' or '}'");
            }
        }

        private List<Object> arr(int depth) {
            List<Object> a = new ArrayList<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == ']') {
                i++;
                return a;
            }
            while (true) {
                ws();
                a.add(value(depth + 1));
                ws();
                if (i >= s.length()) throw err("unexpected end");
                char c = s.charAt(i++);
                if (c == ']') return a;
                if (c != ',') throw err("expected ',' or ']'");
            }
        }

        private String str() {
            StringBuilder b = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c < 0x20) throw err("control character in string");
                if (c != '\\') {
                    b.append(c);
                    continue;
                }
                if (i >= s.length()) throw err("unterminated escape");
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) throw err("short \\u escape");
                        int code = 0;
                        for (int k = 0; k < 4; k++) {
                            int d = Character.digit(s.charAt(i + k), 16);
                            if (d < 0) throw err("bad \\u escape");
                            code = code * 16 + d;
                        }
                        b.append((char) code);
                        i += 4;
                        break;
                    default: throw err("bad escape");
                }
            }
        }

        private Object num() {
            int start = i;
            if (s.charAt(i) == '-') i++;
            if (i >= s.length()) throw err("bad number");
            if (s.charAt(i) == '0') i++;
            else if (Character.isDigit(s.charAt(i))) while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            else throw err("bad number");
            boolean frac = false;
            if (i < s.length() && s.charAt(i) == '.') {
                frac = true;
                i++;
                int d = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == d) throw err("bad number");
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                frac = true;
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int d = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == d) throw err("bad number");
            }
            String t = s.substring(start, i);
            if (!frac) {
                try {
                    return Long.parseLong(t);
                } catch (NumberFormatException x) {
                    // too big for a long: fall through to double
                }
            }
            double d = Double.parseDouble(t);
            if (Double.isInfinite(d)) throw err("number out of range");
            return d;
        }

        public static String write(Object v) {
            StringBuilder b = new StringBuilder();
            write(b, v, 0);
            return b.toString();
        }

        private static void write(StringBuilder b, Object v, int depth) {
            if (depth > MAX_DEPTH) throw new IllegalArgumentException("nested too deeply");
            if (v == null) b.append("null");
            else if (v instanceof String str) quote(b, str);
            else if (v instanceof Boolean) b.append(v);
            else if (v instanceof Double || v instanceof Float) {
                double d = ((Number) v).doubleValue();
                if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("JSON has no NaN/Infinity");
                b.append(v);
            } else if (v instanceof Number) b.append(v);
            else if (v instanceof Map<?, ?> m) {
                b.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if (!first) b.append(',');
                    first = false;
                    quote(b, String.valueOf(e.getKey()));
                    b.append(':');
                    write(b, e.getValue(), depth + 1);
                }
                b.append('}');
            } else if (v instanceof Iterable<?> it) {
                b.append('[');
                boolean first = true;
                for (Object o : it) {
                    if (!first) b.append(',');
                    first = false;
                    write(b, o, depth + 1);
                }
                b.append(']');
            } else if (v instanceof Object[] arr) write(b, List.of(arr), depth);
            else quote(b, v.toString());
        }

        private static void quote(StringBuilder b, String str) {
            b.append('"');
            for (int k = 0; k < str.length(); k++) {
                char c = str.charAt(k);
                switch (c) {
                    case '"': b.append("\\\""); break;
                    case '\\': b.append("\\\\"); break;
                    case '\n': b.append("\\n"); break;
                    case '\r': b.append("\\r"); break;
                    case '\t': b.append("\\t"); break;
                    default:
                        // surrogates are escaped so a lone one survives the trip (and still matches when masked)
                        if (c < 0x20 || c == 0x2028 || c == 0x2029 || Character.isSurrogate(c)) {
                            b.append(String.format("\\u%04x", (int) c));
                        } else {
                            b.append(c);
                        }
                }
            }
            b.append('"');
        }
    }
}
