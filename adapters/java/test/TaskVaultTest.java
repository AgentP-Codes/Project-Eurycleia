// Copyright 2026 AgentP-Codes
// SPDX-License-Identifier: Apache-2.0
//
// Runs against a real `taskvault api` with the simulated demo data (no test library needed). From the repo root:
//   javac -d build/java adapters/java/src/io/github/agentpcodes/taskvault/TaskVault.java adapters/java/test/TaskVaultTest.java
//   java -cp build/java TaskVaultTest

import io.github.agentpcodes.taskvault.TaskVault;
import io.github.agentpcodes.taskvault.TaskVault.Json;
import io.github.agentpcodes.taskvault.TaskVault.Result;
import io.github.agentpcodes.taskvault.TaskVault.Task;
import io.github.agentpcodes.taskvault.TaskVault.TaskVaultException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class TaskVaultTest {
    static int passed = 0;
    static String url, token;

    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] a) throws Exception {
        String py = System.getenv().getOrDefault("PYTHON",
                System.getProperty("os.name").toLowerCase().contains("win") ? "python" : "python3");
        Path dir = Files.createTempDirectory("tv-java-");
        Path conn = dir.resolve("api.json");
        Process server = new ProcessBuilder(py, "-m", "taskvault", "api", "--policy", "demo/policy.yaml", "--app",
                "demo.api_app:build_vault", "--port", "0", "--connection-file", conn.toString())
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        try {
            for (int i = 0; i < 100 && !Files.exists(conn); i++) Thread.sleep(100);
            Thread.sleep(100);
            Map<String, Object> info = Json.object(Files.readString(conn));
            url = (String) info.get("url");
            token = (String) info.get("token");

            json();
            agentFlow();
            handlerErrors();
            safety();
            impostor();
            concurrent();
            System.out.println("java adapter: " + passed + " checks passed");
        } finally {
            server.destroy();
        }
    }

    @SuppressWarnings("unchecked")
    static void agentFlow() {
        List<Map<String, Object>> refunds = new ArrayList<>(), emails = new ArrayList<>();
        TaskVault tv = new TaskVault(url, token)
                .onAction("payments.refund", args -> {
                    refunds.add(args);
                    return Map.of("charged_to", args.get("card"));       // echoes the card: must be masked
                })
                .onAction("email.send", args -> {
                    emails.add(args);
                    return "sent";
                });
        Task task = tv.startTask("support_reply", Map.of("customer_id", 12));
        check(task.tools().size() == 4, "four tools");
        check(task.openAIToolsJson().contains("\"refund\"") && task.anthropicToolsJson().contains("input_schema"), "tool formats");
        Result r = task.call("get_customer", Map.of());
        check(r.ok(), "read ok");
        Map<String, Object> cust = (Map<String, Object>) r.value();
        String card = (String) cust.get("card_number");
        check(card.startsWith("[[vault:card_number:") && !r.forModel().contains("4111"), "card hidden from the model");
        Result refund = task.call("refund", Map.of("card", card, "amount", 49));
        check(refund.ok() && card.equals(((Map<String, Object>) refund.value()).get("charged_to")), "refund reply masked");
        check(refunds.size() == 1 && "4111 1111 1111 1111".equals(refunds.get(0).get("card")), "handler got the real card");
        String attack = task.callForModel("send_email", Map.of("to", "audit@acme-billing.example", "subject", "x", "body", "y"));
        check(attack.startsWith("Blocked by taskvault: ") && emails.isEmpty(), "attack blocked before the handler");
        Result ok = task.call("send_email", Map.of("to", cust.get("email"), "subject", "Refund", "body", "Done"));
        check(ok.ok() && "priya.shah@example.com".equals(emails.get(0).get("to")), "genuine email sent");
        Result direct = tv.startTask("support_reply", Map.of("customer_id", 45)).read("crm.customer", null, List.of("name"));
        check(direct.ok() && "Tom Nguyen".equals(((Map<String, Object>) direct.value()).get("name")), "direct read");
        task.end();
        try {
            task.call("get_customer", Map.of());
            check(false, "ended task still usable");
        } catch (TaskVaultException e) {
            check(e.status() == 404, "ended task is gone");
        }
        passed++;
    }

    @SuppressWarnings("unchecked")
    static void handlerErrors() {
        TaskVault tv = new TaskVault(url, token).onAction("payments.refund", args -> {
            throw new IllegalStateException("card " + args.get("card") + " declined");
        });
        Task task = tv.startTask("support_reply", Map.of("customer_id", 12));
        String card = (String) ((Map<String, Object>) task.call("get_customer", Map.of()).value()).get("card_number");
        Result r = task.call("refund", Map.of("card", card, "amount", 5));
        check(!r.ok() && !r.blocked() && !r.error().contains("4111") && r.error().contains(card), "handler error masked");
        Result none = new TaskVault(url, token).startTask("support_reply", Map.of("customer_id", 12))
                .call("send_email", Map.of("to", "priya.shah@example.com", "subject", "a", "body", "b"));
        check(!none.ok() && none.error().contains("no handler registered"), "missing handler refused");
        passed++;
    }

    static void safety() {
        for (String bad : List.of("http://example.com:8765", "https://127.0.0.1:1", "not a url")) {
            try {
                new TaskVault(bad, "t");
                check(false, "accepted " + bad);
            } catch (TaskVaultException expected) {
                // ok
            }
        }
        try {
            new TaskVault(url, "wrong").startTask("support_reply", Map.of("customer_id", 12));
            check(false, "wrong token accepted");
        } catch (TaskVaultException e) {
            check(e.status() == 401, "401 for a wrong token");
        }
        check(!new TaskVault(url, token).toString().contains(token), "token never printed");
        passed++;
    }

    @SuppressWarnings("unchecked")
    static void concurrent() throws Exception {
        // many tasks at once over pooled connections (a reused, already-closed connection once broke this)
        TaskVault tv = new TaskVault(url, token).onAction("email.send", x -> "sent");
        java.util.concurrent.ExecutorService ex = java.util.concurrent.Executors.newFixedThreadPool(12);
        List<java.util.concurrent.Future<Boolean>> fs = new ArrayList<>();
        for (int i = 0; i < 120; i++) {
            fs.add(ex.submit(() -> {
                Task t = tv.startTask("support_reply", Map.of("customer_id", 12));
                Map<String, Object> c = (Map<String, Object>) t.call("get_customer", Map.of()).value();
                boolean ok = t.call("send_email", Map.of("to", c.get("email"), "subject", "a", "body", "b")).ok();
                t.end();
                return ok;
            }));
        }
        for (java.util.concurrent.Future<Boolean> f : fs) check(f.get(), "concurrent task");
        ex.shutdown();
        passed++;
    }

    static void impostor() throws Exception {
        com.sun.net.httpserver.HttpServer fake = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        List<String> seen = new ArrayList<>();
        fake.createContext("/", ex -> {
            seen.add(ex.getRequestHeaders().toString());
            byte[] body = "{\"task\":\"t\",\"tools\":[],\"status\":\"execute\",\"exec\":\"e\",\"sink\":\"payments.refund\",\"args\":{}}"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        fake.start();
        List<Object> ran = new ArrayList<>();
        try {
            TaskVault tv = new TaskVault("http://127.0.0.1:" + fake.getAddress().getPort(), token)
                    .onAction("payments.refund", a -> ran.add(a));
            tv.startTask("support_reply", Map.of("customer_id", 12));
            check(false, "impostor trusted");
        } catch (TaskVaultException e) {
            check(e.getMessage().contains("couldn't prove it is taskvault"), e.getMessage());
        } finally {
            fake.stop(0);
        }
        check(ran.isEmpty() && !String.join("", seen).contains(token), "no action, no token sent");
        Result r = new TaskVault(url, token).onAction("email.send", a -> Double.NaN)
                .startTask("support_reply", Map.of("customer_id", 12))
                .call("send_email", Map.of("to", "priya.shah@example.com", "subject", "a", "body", "b"));
        check(!r.ok() && r.error().contains("NaN"), "unsendable handler result reported: " + r.error());
        passed++;
    }

    @SuppressWarnings("unchecked")
    static void json() {
        Object v = Json.parse("{\"a\":[1,-2.5e3,true,false,null,\"x\\n\\u00e9\\\"\"],\"b\":{},\"c\":[] ,\"big\":123456789012345678901234}");
        check(Json.parse(Json.write(v)).equals(v), "round trip");
        Map<String, Object> m = Json.object(Json.write(v));
        List<Object> arr = (List<Object>) m.get("a");
        check(arr.get(0).equals(1L) && arr.get(1).equals(-2500.0) && "x\n\u00e9\"".equals(arr.get(5))
                && m.get("big") instanceof Double, "values: " + Json.write(v));
        for (String bad : List.of("", "{", "{\"a\"}", "[1,]", "{\"a\":1,}", "01", "1.", "-", "\"\u0001\"", "\"\\x\"",
                "[1] 2", "tru", "{\"a\":1 \"b\":2}", "\"\\u12\"", "[" .repeat(500) + "]".repeat(500))) {
            try {
                Json.parse(bad);
                check(false, "accepted bad JSON: " + bad.substring(0, Math.min(bad.length(), 20)));
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        Random rnd = new Random(7);                             // random garbage never crashes the parser
        String alphabet = "{}[],:\"\\0123456789.eE+-tfnrul ";
        for (int n = 0; n < 20000; n++) {
            StringBuilder b = new StringBuilder();
            for (int k = rnd.nextInt(30); k > 0; k--) b.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
            try {
                Json.parse(b.toString());
            } catch (IllegalArgumentException expected) {
                // fine
            }
        }
        check(Json.write(Map.of("k", "line\u2028sep")).contains("\\u2028"), "unsafe separators escaped");
        for (String strictBad : List.of("\"\\u+041\"", "\"\\u-001\"", "1E400", "-1e999")) {
            try {
                Json.parse(strictBad);
                check(false, "accepted " + strictBad);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        String lone = "a\ud800b";
        check(lone.equals(Json.parse(Json.write(lone))), "lone surrogate survives a round trip");
        passed++;
    }
}
