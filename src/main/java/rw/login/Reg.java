package rw.login;

import net.kyori.adventure.text.Component;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.mindrot.jbcrypt.BCrypt;

import java.util.UUID;

/** Register / change password / unregister. */
final class Reg {
    private final RWLogin pl;

    Reg(RWLogin pl) {
        this.pl = pl;
    }

    private String validate(Player p, String pw, String pw2) {
        int min = pl.getConfig().getInt("password.min-length", 6);
        int max = pl.getConfig().getInt("password.max-length", 32);
        if (pw == null || pw.length() < min) return "pw-short";
        if (pw.length() > max) return "pw-long";
        if (pw2 != null && !pw.equals(pw2)) return "pw-mismatch";
        if (pl.getConfig().getBoolean("password.deny-same-as-name", true) && pw.equalsIgnoreCase(p.getName())) return "pw-name";
        return null;
    }

    private Component err(String key) {
        return pl.msg(key, pl.ph("min", String.valueOf(pl.getConfig().getInt("password.min-length", 6))),
                pl.ph("max", String.valueOf(pl.getConfig().getInt("password.max-length", 32))));
    }

    void register(Player p, String pw, String pw2) {
        String bad = validate(p, pw, pw2);
        if (bad != null) {
            pl.ui.show(p, true, err(bad));
            return;
        }
        UUID id = p.getUniqueId();
        String key = pl.key(p.getName());
        String ip = pl.ip(p);
        int cost = pl.getConfig().getInt("password.bcrypt-cost", 10);
        pl.db.exec(() -> {
            if (pl.db.find(key) != null) {
                pl.sync(() -> {
                    pl.auth.registered.put(id, true);
                    pl.ui.show(p, false, pl.msg("already-registered"));
                });
                return;
            }
            pl.db.create(key, p.getName(), BCrypt.hashpw(pw, BCrypt.gensalt(cost)), ip);
            pl.sync(() -> {
                pl.auth.registered.put(id, true);
                pl.success(p, "register-success");
            });
        });
    }

    void change(Player p, String oldPw, String newPw) {
        String bad = validate(p, newPw, null);
        if (bad != null) {
            p.sendMessage(err(bad));
            return;
        }
        String key = pl.key(p.getName());
        int cost = pl.getConfig().getInt("password.bcrypt-cost", 10);
        pl.db.exec(() -> {
            Db.Account a = pl.db.find(key);
            boolean ok = a != null && BCrypt.checkpw(oldPw, a.hash());
            if (ok) pl.db.setHash(key, BCrypt.hashpw(newPw, BCrypt.gensalt(cost)));
            boolean done = ok;
            pl.sync(() -> p.sendMessage(pl.msg(done ? "changed" : "change-wrong")));
        });
    }

    void unregister(CommandSender s, String name) {
        String key = pl.key(name);
        pl.db.exec(() -> {
            boolean ok = pl.db.delete(key);
            pl.sync(() -> {
                s.sendMessage(pl.msg(ok ? "unregistered" : "unregister-none", pl.ph("player", name)));
                Player t = org.bukkit.Bukkit.getPlayerExact(name);
                if (ok && t != null) t.kick(pl.msg("unregistered-kick"));
            });
        });
    }
          }
