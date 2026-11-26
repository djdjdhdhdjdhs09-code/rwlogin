package rw.login;

import net.kyori.adventure.text.Component;
import org.bukkit.entity.Player;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Login / register / change password logic. Heavy work runs on the database thread. */
final class Auth {
    private final RWLogin pl;
    final Map<UUID, Boolean> registered = new ConcurrentHashMap<>();

    Auth(RWLogin pl) {
        this.pl = pl;
    }

    boolean isRegistered(Player p) {
        return registered.getOrDefault(p.getUniqueId(), true);
    }

    /** A player just joined: decide between register, login or auto-login. */
    void begin(Player p) {
        UUID id = p.getUniqueId();
        pl.authed.remove(id);
        pl.joinAt.put(id, System.currentTimeMillis());
        String key = pl.key(p.getName());
        String ip = pl.ip(p);
        pl.db.exec(() -> {
            Db.Account a = pl.db.find(key);
            pl.sync(() -> {
                if (!p.isOnline()) return;
                registered.put(id, a != null);
                long min = pl.getConfig().getLong("security.auto-login-minutes", 0);
                if (a != null && min > 0 && ip.equals(a.lastIp())
                        && System.currentTimeMillis() - a.lastLogin() < min * 60000L) {
                    pl.success(p, "login-success");
                } else {
                    pl.ui.show(p, a == null, null);
                }
            });
        });
    }

    void quit(Player p) {
        UUID id = p.getUniqueId();
        pl.authed.remove(id);
        pl.joinAt.remove(id);
        registered.remove(id);
    }

    void login(Player p, String pw) {
        if (pw == null || pw.isEmpty()) {
            pl.ui.show(p, false, pl.msg("wrong-password"));
            return;
        }
        UUID id = p.getUniqueId();
        String key = pl.key(p.getName());
        String ip = pl.ip(p);
        int max = pl.getConfig().getInt("security.max-attempts", 3);
        int warn = pl.getConfig().getInt("security.warn-after-attempts", 2);
        long lock = pl.getConfig().getLong("security.lockout-seconds", 600);
        pl.db.exec(() -> {
            Db.Account a = pl.db.find(key);
            long now = System.currentTimeMillis();
            if (a == null) {
                pl.sync(() -> {
                    registered.put(id, false);
                    pl.ui.show(p, true, null);
                });
                return;
            }
            if (a.lockedUntil() > now) {
                long left = (a.lockedUntil() - now + 999) / 1000;
                pl.sync(() -> p.kick(pl.msg("locked-kick", pl.ph("time", pl.fmt(left)))));
                return;
            }
            boolean ok;
            try {
                ok = BCrypt.checkpw(pw, a.hash());
            } catch (IllegalArgumentException ex) {
                ok = false;
            }
            if (ok) {
                pl.db.setFails(key, 0, 0);
                pl.db.markLogin(key, ip);
                pl.sync(() -> pl.success(p, "login-success"));
                return;
            }
            int f = a.fails() + 1;
            if (f >= max) {
                pl.db.setFails(key, 0, now + lock * 1000L);
                pl.getLogger().warning(p.getName() + " locked for " + lock + "s after " + f + " wrong passwords (" + ip + ")");
                pl.sync(() -> p.kick(pl.msg("locked-kick", pl.ph("time", pl.fmt(lock)))));
            } else {
                pl.db.setFails(key, f, 0);
                int left = max - f;
                pl.sync(() -> {
                    Component e = pl.msg("wrong-password");
                    if (f >= warn) {
                        e = e.appendNewline().append(pl.msg("warning", pl.ph("attempts", String.valueOf(left)), pl.ph("time", pl.fmt(lock))));
                    }
                    pl.ui.show(p, false, e);
                });
            }
        });
    }
                   }
