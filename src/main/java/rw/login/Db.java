package rw.login;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/** SQLite storage. Every call runs on one dedicated thread (never the main thread). */
final class Db {
    interface Task {
        void run() throws Exception;
    }

    record Account(String key, String display, String hash, int fails, long lockedUntil, String lastIp, long lastLogin) {
    }

    private final Connection c;
    private final ExecutorService ex;
    private final Logger log;

    Db(File file, Logger log) throws Exception {
        this.log = log;
        file.getParentFile().mkdirs();
        Class.forName("org.sqlite.JDBC");
        c = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath());
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("PRAGMA synchronous=FULL");
            s.execute("CREATE TABLE IF NOT EXISTS accounts (name TEXT PRIMARY KEY, display TEXT, hash TEXT NOT NULL,"
                    + " fails INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0, last_ip TEXT,"
                    + " last_login INTEGER DEFAULT 0, registered INTEGER DEFAULT 0)");
        }
        ex = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "RWLogin-DB");
            t.setDaemon(true);
            return t;
        });
    }

    /** Run a task on the database thread. */
    void exec(Task t) {
        ex.execute(() -> {
            try {
                t.run();
            } catch (Throwable x) {
                log.warning("Database task failed: " + x);
            }
        });
    }

    /** Run on the database thread and wait for the result (only call from async threads). */
    <T> T query(Callable<T> job) throws Exception {
        return ex.submit(job).get(5, TimeUnit.SECONDS);
    }

    Account find(String key) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT display,hash,fails,locked_until,last_ip,last_login FROM accounts WHERE name=?")) {
            ps.setString(1, key);
            try (ResultSet r = ps.executeQuery()) {
                if (!r.next()) return null;
                return new Account(key, r.getString(1), r.getString(2), r.getInt(3), r.getLong(4), r.getString(5), r.getLong(6));
            }
        }
    }

    void create(String key, String display, String hash, String ip) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO accounts (name,display,hash,last_ip,last_login,registered) VALUES (?,?,?,?,?,?)")) {
            ps.setString(1, key);
            ps.setString(2, display);
            ps.setString(3, hash);
            ps.setString(4, ip);
            ps.setLong(5, System.currentTimeMillis());
            ps.setLong(6, System.currentTimeMillis());
            ps.executeUpdate();
        }
    }

    void setHash(String key, String hash) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("UPDATE accounts SET hash=? WHERE name=?")) {
            ps.setString(1, hash);
            ps.setString(2, key);
            ps.executeUpdate();
        }
    }

    void setFails(String key, int fails, long lockedUntil) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("UPDATE accounts SET fails=?, locked_until=? WHERE name=?")) {
            ps.setInt(1, fails);
            ps.setLong(2, lockedUntil);
            ps.setString(3, key);
            ps.executeUpdate();
        }
    }

    void markLogin(String key, String ip) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("UPDATE accounts SET last_ip=?, last_login=? WHERE name=?")) {
            ps.setString(1, ip);
            ps.setLong(2, System.currentTimeMillis());
            ps.setString(3, key);
            ps.executeUpdate();
        }
    }

    boolean delete(String key) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("DELETE FROM accounts WHERE name=?")) {
            ps.setString(1, key);
            return ps.executeUpdate() > 0;
        }
    }

    void close() {
        ex.shutdown();
        try {
            ex.awaitTermination(5, TimeUnit.SECONDS);
            c.close();
        } catch (Exception ignored) {
        }
    }
    }
