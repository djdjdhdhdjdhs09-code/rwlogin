package rw.login;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.entity.Player;

import java.util.List;
import java.util.Locale;

final class Cmds implements TabExecutor {
    private final RWLogin pl;

    Cmds(RWLogin pl) {
        this.pl = pl;
    }

    @Override
    public boolean onCommand(CommandSender s, Command c, String label, String[] a) {
        String name = c.getName().toLowerCase(Locale.ROOT);
        if (name.equals("rwlogin")) {
            if (!s.hasPermission("rwlogin.admin")) {
                s.sendMessage(pl.msg("no-permission"));
                return true;
            }
            if (a.length >= 1 && a[0].equalsIgnoreCase("reload")) {
                pl.reloadConfig();
                s.sendMessage(pl.msg("reloaded"));
            } else if (a.length >= 2 && a[0].equalsIgnoreCase("unregister")) {
                pl.reg.unregister(s, a[1]);
            } else {
                s.sendMessage(net.kyori.adventure.text.Component.text("/rwlogin <reload|unregister <player>>"));
            }
            return true;
        }
        if (!(s instanceof Player p)) return true;
        switch (name) {
            case "login" -> {
                if (pl.isAuthed(p)) {
                    p.sendMessage(pl.msg("already-authed"));
                } else if (a.length == 0) {
                    pl.ui.show(p, !pl.auth.isRegistered(p), null);
                } else {
                    pl.auth.login(p, a[0]);
                }
            }
            case "register" -> {
                if (pl.isAuthed(p)) p.sendMessage(pl.msg("already-authed"));
                else if (a.length == 0) pl.ui.show(p, true, null);
                else if (a.length < 2) p.sendMessage(pl.msg("usage-register"));
                else pl.reg.register(p, a[0], a[1]);
            }
            default -> {
                if (!pl.isAuthed(p)) p.sendMessage(pl.msg("not-authed"));
                else if (a.length < 2) p.sendMessage(pl.msg("usage-change"));
                else pl.reg.change(p, a[0], a[1]);
            }
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender s, Command c, String l, String[] a) {
        if (c.getName().equalsIgnoreCase("rwlogin") && a.length == 1 && s.hasPermission("rwlogin.admin")) {
            return List.of("reload", "unregister").stream().filter(x -> x.startsWith(a[0].toLowerCase(Locale.ROOT))).toList();
        }
        return List.of();
    }
            }
