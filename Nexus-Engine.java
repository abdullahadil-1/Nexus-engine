import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/*
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║                NEXUS ENGINE v3.1 ENTERPRISE EDITION                ║
 * ║          Secure VM + In-Memory DB + Persistence Layer              ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 *
 * SECURITY FIXES OVER v3.0:
 * ✔ [CRITICAL]  Replaced Java deserialization (ObjectInputStream) with a
 *               safe custom text-based format — eliminates RCE via gadget chains
 * ✔ [HIGH]      Path traversal protection on SAVE / LOAD filenames
 * ✔ [HIGH]      Strict operator whitelist in QUERY — prevents injection
 * ✔ [MEDIUM]    AtomicInteger for lastResult — eliminates race condition
 * ✔ [MEDIUM]    INC / DEC now fail loudly when variable is absent
 * ✔ [MEDIUM]    DROP requires explicit confirmation (DROP CONFIRM)
 * ✔ [MEDIUM]    Record ID length capped (MAX_ID_LENGTH)
 * ✔ [MEDIUM]    Field key restricted to [a-zA-Z0-9_] — no injection via keys
 * ✔ [LOW]       Double equality uses epsilon comparison, not ==
 * ✔ [LOW]       autoSave logs failure instead of silently swallowing it
 * ✔ [LOW]       LOAD is atomic — full rollback on parse error (no partial state)
 * ✔ [LOW]       Levenshtein input bounded to prevent quadratic blow-up
 */

public class NexusEngine {

    public static void main(String[] args) {
        new NexusEngine().start();
    }

    private final RuntimeEngine runtime = new RuntimeEngine();

    private void start() {
        Term.banner();

        Scanner sc = new Scanner(System.in);
        Term.info("VM MODE | HELP | DB | EXIT");

        outer:
        while (true) {
            Term.prompt("VM");

            if (!sc.hasNextLine()) {
                Term.warn("EOF detected. Shutting down.");
                break;
            }

            String line = sc.nextLine().trim();
            if (line.isEmpty()) continue;

            switch (line.toUpperCase()) {
                case "EXIT" -> {
                    runtime.autoSave();
                    Term.warn("Engine shutdown complete.");
                    return;
                }
                case "DB" -> {
                    Term.info("Switching to DB mode...");
                    break outer;
                }
                default -> runtime.execute(line);
            }
        }

        DatabaseEngine db = runtime.getDatabase();
        Term.info("DB MODE | HELP | EXIT");

        while (true) {
            Term.prompt("DB");

            if (!sc.hasNextLine()) {
                Term.warn("EOF detected. Shutting down.");
                break;
            }

            String line = sc.nextLine().trim();
            if (line.isEmpty()) continue;

            if (line.equalsIgnoreCase("EXIT")) {
                runtime.autoSave();
                Term.warn("Engine shutdown complete.");
                break;
            }

            db.execute(line);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
class Term {

    private static final String RESET   = "\u001B[0m";
    private static final String RED     = "\u001B[31m";
    private static final String GREEN   = "\u001B[32m";
    private static final String YELLOW  = "\u001B[33m";
    private static final String CYAN    = "\u001B[36m";
    private static final String WHITE   = "\u001B[97m";
    private static final String MAGENTA = "\u001B[35m";
    private static final String BOLD    = "\u001B[1m";

    static void banner() {
        System.out.println(CYAN + BOLD);
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║               NEXUS ENGINE v3.1                          ║");
        System.out.println("║     Secure VM + Persistent Database Engine               ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println(RESET);
    }

    static void prompt(String mode) {
        String color = mode.equals("VM") ? CYAN : MAGENTA;
        System.out.print(color + "\n[" + mode + "] » " + RESET);
    }

    static void success(String msg) { System.out.println(GREEN   + "✔ " + msg + RESET); }
    static void error(String msg)   { System.out.println(RED     + "✘ " + msg + RESET); }
    static void warn(String msg)    { System.out.println(YELLOW  + "⚠ " + msg + RESET); }
    static void info(String msg)    { System.out.println(CYAN    + "ℹ " + msg + RESET); }
    static void result(String msg)  { System.out.println(WHITE   + "➜ " + msg + RESET); }

    static void separator() {
        System.out.println("──────────────────────────────────────────────────────────");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
class Parser {

    private static final Pattern TOKEN_PATTERN =
            Pattern.compile("\"([^\"]*)\"|(\\S+)");

    public static List<String> tokenize(String input) {
        List<String> tokens = new ArrayList<>();
        Matcher matcher = TOKEN_PATTERN.matcher(input);
        while (matcher.find()) {
            tokens.add(matcher.group(1) != null ? matcher.group(1) : matcher.group(2));
        }
        return tokens;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
class OpLog {

    private final Deque<String> log = new ArrayDeque<>();
    private static final int MAX_LOGS = 100;
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void record(String line) {
        String entry = "[" + LocalDateTime.now().format(FORMAT) + "] " + line;
        log.addFirst(entry);
        if (log.size() > MAX_LOGS) log.removeLast();
    }

    public void show() {
        if (log.isEmpty()) { Term.warn("No history."); return; }
        Term.separator();
        log.forEach(System.out::println);
        Term.separator();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
/**
 * Safe persistence helper.
 * FIX [CRITICAL]: Replaced Java serialization (ObjectInputStream /
 * ObjectOutputStream) with a plain-text format.  Java deserialization of
 * untrusted files is a well-known Remote Code Execution vector (CVE class
 * CWE-502) exploitable through gadget chains present in many JDK versions.
 * The custom format holds no executable class data, so a malicious .nxs file
 * cannot execute arbitrary code on load.
 *
 * File format (UTF-8, line-oriented):
 *   LASTRESULT <int>
 *   VAR <name> <int>
 *   REC <id> <field>=<value> [<field>=<value> ...]
 */
class Persistence {

    // FIX [HIGH]: Restrict save/load paths to the current working directory
    // and a safe filename pattern to prevent path traversal attacks.
    private static final Pattern SAFE_FILENAME =
            Pattern.compile("^[a-zA-Z0-9_\\-]+\\.nxs$");

    static Path safePath(String filename) {
        if (!SAFE_FILENAME.matcher(filename).matches())
            throw new IllegalArgumentException(
                    "Filename must match [a-zA-Z0-9_-]+.nxs  e.g. save.nxs");

        // Resolve against cwd and double-check no directory components snuck in.
        Path base = Paths.get("").toAbsolutePath();
        Path target = base.resolve(filename).normalize();

        if (!target.startsWith(base))
            throw new IllegalArgumentException("Path traversal attempt blocked.");

        return target;
    }

    /** Serialize runtime + database to the safe text format. */
    static void save(String filename,
                     Map<String, Integer> vars,
                     int lastResult,
                     Map<String, Map<String, String>> table) throws IOException {

        Path path = safePath(filename);
        StringBuilder sb = new StringBuilder();

        sb.append("LASTRESULT ").append(lastResult).append('\n');

        for (Map.Entry<String, Integer> e : vars.entrySet())
            sb.append("VAR ").append(e.getKey()).append(' ').append(e.getValue()).append('\n');

        for (Map.Entry<String, Map<String, String>> rec : table.entrySet()) {
            sb.append("REC ").append(rec.getKey());
            for (Map.Entry<String, String> f : rec.getValue().entrySet())
                sb.append(' ').append(f.getKey()).append('=').append(f.getValue());
            sb.append('\n');
        }

        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
    }

    /**
     * Deserialize from the safe text format.
     * FIX [LOW]: Load is fully validated before any state is mutated,
     * so a corrupt file leaves the runtime unchanged (atomic swap).
     */
    static LoadResult load(String filename) throws IOException {

        Path path = safePath(filename);
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);

        Map<String, Integer> vars  = new LinkedHashMap<>();
        Map<String, Map<String, String>> table = new LinkedHashMap<>();
        int lastResult = 0;

        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty()) continue;

            if (line.startsWith("LASTRESULT ")) {
                lastResult = Integer.parseInt(line.substring(11).trim());

            } else if (line.startsWith("VAR ")) {
                String[] parts = line.substring(4).trim().split(" ", 2);
                if (parts.length != 2)
                    throw new IOException("Corrupt VAR line: " + line);
                vars.put(parts[0], Integer.parseInt(parts[1]));

            } else if (line.startsWith("REC ")) {
                String[] tokens = line.substring(4).trim().split(" ");
                if (tokens.length < 1)
                    throw new IOException("Corrupt REC line: " + line);
                String id = tokens[0];
                Map<String, String> row = new LinkedHashMap<>();
                for (int i = 1; i < tokens.length; i++) {
                    String[] kv = tokens[i].split("=", 2);
                    if (kv.length != 2)
                        throw new IOException("Corrupt field in REC: " + tokens[i]);
                    row.put(kv[0], kv[1]);
                }
                table.put(id, row);

            } else {
                throw new IOException("Unrecognised line in save file: " + line);
            }
        }

        return new LoadResult(vars, table, lastResult);
    }

    record LoadResult(Map<String, Integer> vars,
                      Map<String, Map<String, String>> table,
                      int lastResult) {}
}

// ─────────────────────────────────────────────────────────────────────────────
class RuntimeEngine {

    private static final int MAX_VARIABLES    = 1000;
    private static final int MAX_CMD_LENGTH   = 2048; // guard against huge inputs

    private final Map<String, Integer> vars = new ConcurrentHashMap<>();
    private final DatabaseEngine database   = new DatabaseEngine();
    private final OpLog log                 = new OpLog();

    // FIX [MEDIUM]: Use AtomicInteger so concurrent reads/writes to lastResult
    // are race-condition-free without requiring manual synchronisation.
    private final AtomicInteger lastResult = new AtomicInteger(0);

    DatabaseEngine getDatabase() { return database; }

    public void execute(String line) {

        if (line.length() > MAX_CMD_LENGTH) {
            Term.error("Input too long (max " + MAX_CMD_LENGTH + " chars).");
            return;
        }

        log.record(line);
        List<String> parts = Parser.tokenize(line);
        if (parts.isEmpty()) return;

        String cmd = parts.get(0).toUpperCase();

        try {
            switch (cmd) {
                case "SET"     -> set(parts);
                case "ADD"     -> arithmetic(parts, '+');
                case "SUB"     -> arithmetic(parts, '-');
                case "MUL"     -> arithmetic(parts, '*');
                case "DIV"     -> arithmetic(parts, '/');
                case "MOD"     -> arithmetic(parts, '%');
                case "INC"     -> inc(parts);
                case "DEC"     -> dec(parts);
                case "PRINT"   -> print(parts);
                case "SHOW"    -> show();
                case "CLEAR"   -> clear();
                case "STORE"   -> store(parts);
                case "SAVE"    -> save(parts);
                case "LOAD"    -> load(parts);
                case "HISTORY" -> log.show();
                case "MEMORY"  -> memory();
                case "HELP"    -> help();
                default        -> unknown(cmd);
            }
        } catch (Exception e) {
            Term.error(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
    }

    // ── Variable name validation ──────────────────────────────────────────────
    private static final Pattern VALID_VAR = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]{0,63}$");

    private static void validateVarName(String name) {
        if (!VALID_VAR.matcher(name).matches())
            throw new IllegalArgumentException(
                    "Variable name must be [a-zA-Z_][a-zA-Z0-9_]{0,63}: " + name);
    }

    // ── Commands ──────────────────────────────────────────────────────────────

    private void set(List<String> p) {
        require(p, 3, "SET name value");
        validateVarName(p.get(1));
        if (!vars.containsKey(p.get(1)) && vars.size() >= MAX_VARIABLES)
            throw new IllegalStateException("Variable limit reached (" + MAX_VARIABLES + ").");
        int value = resolve(p.get(2));
        vars.put(p.get(1), value);
        Term.success(p.get(1) + " = " + value);
    }

    private void arithmetic(List<String> p, char op) {
        require(p, 3, "ARITHMETIC a b");
        int a = resolve(p.get(1));
        int b = resolve(p.get(2));
        int result = switch (op) {
            case '+' -> Math.addExact(a, b);
            case '-' -> Math.subtractExact(a, b);
            case '*' -> Math.multiplyExact(a, b);
            case '/' -> {
                if (b == 0) throw new ArithmeticException("Division by zero.");
                yield a / b;
            }
            case '%' -> {
                if (b == 0) throw new ArithmeticException("Modulo by zero.");
                yield a % b;
            }
            default  -> throw new IllegalArgumentException("Unknown operator: " + op);
        };
        lastResult.set(result);
        Term.result("Result = " + result);
    }

    // FIX [MEDIUM]: Original INC/DEC used computeIfPresent which silently
    // did nothing if the variable was absent.  Now they throw clearly.
    private void inc(List<String> p) {
        require(p, 2, "INC variable");
        String name = p.get(1);
        if (!vars.containsKey(name))
            throw new IllegalArgumentException("Variable not found: " + name);
        vars.compute(name, (k, v) -> Math.addExact(v, 1));
        Term.success(name + " = " + vars.get(name));
    }

    private void dec(List<String> p) {
        require(p, 2, "DEC variable");
        String name = p.get(1);
        if (!vars.containsKey(name))
            throw new IllegalArgumentException("Variable not found: " + name);
        vars.compute(name, (k, v) -> Math.subtractExact(v, 1));
        Term.success(name + " = " + vars.get(name));
    }

    private void print(List<String> p) {
        require(p, 2, "PRINT variable|result");
        if (p.get(1).equalsIgnoreCase("result")) {
            Term.result(String.valueOf(lastResult.get()));
            return;
        }
        if (!vars.containsKey(p.get(1)))
            throw new IllegalArgumentException("Variable not found: " + p.get(1));
        Term.result(p.get(1) + " = " + vars.get(p.get(1)));
    }

    private void show() {
        if (vars.isEmpty()) { Term.warn("No variables."); return; }
        Term.separator();
        vars.forEach((k, v) -> System.out.println(k + " = " + v));
        Term.separator();
    }

    private void clear() {
        vars.clear();
        lastResult.set(0);
        Term.success("Variables cleared.");
    }

    private void store(List<String> p) {
        require(p, 2, "STORE variable");
        validateVarName(p.get(1));
        vars.put(p.get(1), lastResult.get());
        Term.success("Stored " + lastResult.get() + " into " + p.get(1));
    }

    private int resolve(String token) {
        try { return Integer.parseInt(token); }
        catch (NumberFormatException ignored) {}
        if (!vars.containsKey(token))
            throw new IllegalArgumentException("Unknown variable: " + token);
        return vars.get(token);
    }

    private void save(List<String> p) throws IOException {
        require(p, 2, "SAVE filename.nxs");
        Persistence.save(p.get(1), vars, lastResult.get(), database.snapshot());
        Term.success("Runtime saved to " + p.get(1));
    }

    // FIX [LOW]: State is only replaced after the entire file parses cleanly.
    private void load(List<String> p) throws IOException {
        require(p, 2, "LOAD filename.nxs");
        Persistence.LoadResult r = Persistence.load(p.get(1));

        vars.clear();
        vars.putAll(r.vars());
        database.replace(r.table());
        lastResult.set(r.lastResult());

        Term.success("Runtime loaded from " + p.get(1));
    }

    // FIX [LOW]: autoSave now logs failure so data loss is visible.
    public void autoSave() {
        try {
            Persistence.save("autosave.nxs", vars, lastResult.get(), database.snapshot());
            Term.success("Auto-saved to autosave.nxs");
        } catch (Exception e) {
            Term.warn("Auto-save FAILED: " + e.getMessage());
        }
    }

    private void memory() {
        Runtime r = Runtime.getRuntime();
        long total = r.totalMemory() / 1024 / 1024;
        long free  = r.freeMemory()  / 1024 / 1024;
        Term.result("Used  : " + (total - free) + " MB");
        Term.result("Free  : " + free            + " MB");
        Term.result("Heap  : " + total            + " MB");
        Term.result("Vars  : " + vars.size() + " / " + MAX_VARIABLES);
    }

    private void help() {
        Term.separator();
        System.out.println("SET x 10          — assign variable");
        System.out.println("ADD x 5           — arithmetic (SUB / MUL / DIV / MOD)");
        System.out.println("INC x / DEC x     — increment / decrement");
        System.out.println("STORE total       — save last result to variable");
        System.out.println("PRINT total       — print variable (or PRINT result)");
        System.out.println("SHOW              — list all variables");
        System.out.println("CLEAR             — clear all variables");
        System.out.println("SAVE save.nxs     — persist state");
        System.out.println("LOAD save.nxs     — restore state");
        System.out.println("MEMORY            — heap statistics");
        System.out.println("HISTORY           — recent commands");
        System.out.println("DB                — switch to database mode");
        Term.separator();
    }

    // FIX [LOW]: Bound input length before Levenshtein to prevent O(n²) blow-up.
    private static final int MAX_LEVENSHTEIN_INPUT = 32;

    private void unknown(String cmd) {
        List<String> known = List.of(
                "SET", "ADD", "SUB", "MUL", "DIV",
                "MOD", "INC", "DEC", "STORE",
                "PRINT", "SHOW", "CLEAR", "SAVE",
                "LOAD", "MEMORY", "HELP", "HISTORY", "DB"
        );

        String truncated = cmd.length() > MAX_LEVENSHTEIN_INPUT
                ? cmd.substring(0, MAX_LEVENSHTEIN_INPUT) : cmd;

        String suggestion = known.stream()
                .min(Comparator.comparingInt(a -> levenshtein(a, truncated)))
                .orElse("HELP");

        Term.error("Unknown command: " + cmd + "  — did you mean: " + suggestion + "?");
    }

    private int levenshtein(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;
        for (int i = 1; i <= a.length(); i++)
            for (int j = 1; j <= b.length(); j++)
                dp[i][j] = Math.min(
                        Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1),
                        dp[i-1][j-1] + (a.charAt(i-1) == b.charAt(j-1) ? 0 : 1));
        return dp[a.length()][b.length()];
    }

    private void require(List<String> p, int min, String usage) {
        if (p.size() < min)
            throw new IllegalArgumentException("Usage: " + usage);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
class DatabaseEngine {

    private static final int MAX_RECORDS      = 5000;
    private static final int MAX_FIELD_LENGTH = 256;

    // FIX [MEDIUM]: Bound record IDs to stop memory exhaustion via huge keys.
    private static final int MAX_ID_LENGTH    = 64;

    // FIX [MEDIUM]: Restrict field keys to safe characters to prevent injection.
    private static final Pattern VALID_KEY = Pattern.compile("^[a-zA-Z0-9_]{1,64}$");

    // FIX [HIGH]: Explicit whitelist of permitted query operators.
    private static final Set<String> ALLOWED_OPS =
            Set.of(">", "<", ">=", "<=", "==", "!=");

    private final Map<String, Map<String, String>> table = new ConcurrentHashMap<>();

    public void execute(String line) {
        List<String> p = Parser.tokenize(line);
        if (p.isEmpty()) return;

        String cmd = p.get(0).toUpperCase();

        try {
            switch (cmd) {
                case "INSERT" -> insert(p);
                case "FIND"   -> find(p);
                case "UPDATE" -> update(p);
                case "DELETE" -> delete(p);
                case "SHOW"   -> show();
                case "COUNT"  -> count();
                case "QUERY"  -> query(p);
                case "DROP"   -> drop(p);
                case "HELP"   -> help();
                default       -> Term.error("Unknown DB command. Type HELP.");
            }
        } catch (Exception e) {
            Term.error(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
    }

    private void insert(List<String> p) {
        require(p, 3, "INSERT id field=value [field=value ...]");

        if (table.size() >= MAX_RECORDS)
            throw new IllegalStateException("Record limit reached (" + MAX_RECORDS + ").");

        String id = validateId(p.get(1));

        if (table.containsKey(id))
            throw new IllegalArgumentException("Record already exists: " + id);

        Map<String, String> row = new ConcurrentHashMap<>();

        for (int i = 2; i < p.size(); i++) {
            String[] kv = p.get(i).split("=", 2);
            if (kv.length != 2)
                throw new IllegalArgumentException("Invalid field syntax (expected key=value): " + p.get(i));
            validateFieldKey(kv[0]);
            if (kv[1].length() > MAX_FIELD_LENGTH)
                throw new IllegalArgumentException("Field value too large (max " + MAX_FIELD_LENGTH + "): " + kv[0]);
            row.put(kv[0].toLowerCase(), kv[1]);
        }

        table.put(id, row);
        Term.success("Inserted record " + id);
    }

    private void find(List<String> p) {
        require(p, 2, "FIND id");
        Map<String, String> row = table.get(p.get(1));
        if (row == null) { Term.warn("Record not found."); return; }
        Term.separator();
        row.forEach((k, v) -> System.out.println(k + " = " + v));
        Term.separator();
    }

    private void update(List<String> p) {
        require(p, 4, "UPDATE id field value");
        String id = p.get(1);
        if (!table.containsKey(id))
            throw new IllegalArgumentException("Record not found: " + id);
        validateFieldKey(p.get(2));
        if (p.get(3).length() > MAX_FIELD_LENGTH)
            throw new IllegalArgumentException("Value too large (max " + MAX_FIELD_LENGTH + ").");
        table.get(id).put(p.get(2).toLowerCase(), p.get(3));
        Term.success("Updated " + id + "." + p.get(2).toLowerCase());
    }

    private void delete(List<String> p) {
        require(p, 2, "DELETE id");
        if (table.remove(p.get(1)) != null)
            Term.success("Deleted " + p.get(1));
        else
            Term.warn("Record not found: " + p.get(1));
    }

    private void show() {
        if (table.isEmpty()) { Term.warn("Empty table."); return; }
        Term.separator();
        table.forEach((id, row) -> System.out.println(id + " => " + row));
        Term.separator();
    }

    private void count() {
        Term.result("Records: " + table.size() + " / " + MAX_RECORDS);
    }

    private void query(List<String> p) {
        require(p, 4, "QUERY field op value  (op: > < >= <= == !=)");

        String field = p.get(1).toLowerCase();
        String op    = p.get(2);
        String value = p.get(3);

        // FIX [HIGH]: Reject any operator not in the explicit whitelist.
        if (!ALLOWED_OPS.contains(op))
            throw new IllegalArgumentException(
                    "Invalid operator '" + op + "'. Allowed: " + ALLOWED_OPS);

        List<Map.Entry<String, Map<String, String>>> results = table.entrySet().stream()
                .filter(e -> e.getValue().containsKey(field))
                .filter(e -> compare(e.getValue().get(field), op, value))
                .collect(Collectors.toList());

        if (results.isEmpty()) { Term.warn("No matches."); return; }

        Term.separator();
        for (var r : results)
            System.out.println(r.getKey() + " => " + r.getValue());
        Term.separator();
    }

    private boolean compare(String a, String op, String b) {
        try {
            double x = Double.parseDouble(a);
            double y = Double.parseDouble(b);

            // FIX [LOW]: Use epsilon for equality so floating-point representation
            // does not produce surprising "not equal" results for identical values.
            final double EPSILON = 1e-9;

            return switch (op) {
                case ">"  -> x >  y;
                case "<"  -> x <  y;
                case ">=" -> x >= y;
                case "<=" -> x <= y;
                case "==" -> Math.abs(x - y) <= EPSILON;
                case "!=" -> Math.abs(x - y) >  EPSILON;
                default   -> false; // unreachable — already whitelisted above
            };
        } catch (NumberFormatException e) {
            return switch (op) {
                case "==" -> a.equalsIgnoreCase(b);
                case "!=" -> !a.equalsIgnoreCase(b);
                default   -> false;
            };
        }
    }

    // FIX [MEDIUM]: DROP now requires "DROP CONFIRM" to prevent accidental wipe.
    private void drop(List<String> p) {
        if (p.size() < 2 || !p.get(1).equalsIgnoreCase("CONFIRM"))
            throw new IllegalArgumentException(
                    "Safety: type  DROP CONFIRM  to wipe the entire database.");
        table.clear();
        Term.success("Database cleared.");
    }

    private void help() {
        Term.separator();
        System.out.println("INSERT u1 name=Ali age=20     — create record");
        System.out.println("FIND u1                       — look up record");
        System.out.println("UPDATE u1 age 21              — update a field");
        System.out.println("DELETE u1                     — remove record");
        System.out.println("QUERY age > 18                — filter (> < >= <= == !=)");
        System.out.println("SHOW                          — dump all records");
        System.out.println("COUNT                         — record count");
        System.out.println("DROP CONFIRM                  — wipe database (irreversible)");
        Term.separator();
    }

    /** Return an unmodifiable snapshot of the table for persistence. */
    Map<String, Map<String, String>> snapshot() {
        Map<String, Map<String, String>> copy = new LinkedHashMap<>();
        table.forEach((id, row) -> copy.put(id, Collections.unmodifiableMap(new LinkedHashMap<>(row))));
        return Collections.unmodifiableMap(copy);
    }

    /** Replace the live table from a loaded snapshot (called by RuntimeEngine.load). */
    void replace(Map<String, Map<String, String>> incoming) {
        table.clear();
        incoming.forEach((id, row) -> table.put(id, new ConcurrentHashMap<>(row)));
    }

    // ── Validators ────────────────────────────────────────────────────────────

    private static String validateId(String id) {
        if (id.length() > MAX_ID_LENGTH)
            throw new IllegalArgumentException(
                    "ID too long (max " + MAX_ID_LENGTH + " chars).");
        return id;
    }

    private static void validateFieldKey(String key) {
        if (!VALID_KEY.matcher(key).matches())
            throw new IllegalArgumentException(
                    "Field key must match [a-zA-Z0-9_]{1,64}: " + key);
    }

    private void require(List<String> p, int min, String usage) {
        if (p.size() < min)
            throw new IllegalArgumentException("Usage: " + usage);
    }
}