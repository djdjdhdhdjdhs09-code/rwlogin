package rw.login;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class RWLogin extends JavaPlugin {
    static final MiniMessage MM = MiniMessage.miniMessage();
    final Set<UUID> authed = ConcurrentHashMap.newKeySet();
    final Map<UUID, Long> joinAt = new ConcurrentHashMap<>();
    Db db;
    Auth auth;
    Reg reg;
    Ui ui;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        try {
            db = new Db(new File(getDataFolder(), getConfig().getString("database.file", "rwlogin.db")), getLogger());
        } catch (Exception ex) {
            getLogger().severe("Cannot open the SQLite database: " + ex);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        auth = new Auth(this);
        reg = new Reg(this);
        ui = new Ui(this);
        getServer().getPluginManager().registerEvents(new Guard(this), this);
        Cmds cmds = new Cmds(this);
        for (String n : List.of("login", "register", "changepassword", "rwlogin")) {
            getCommand(n).setExecutor(cmds);
            getCommand(n).setTabCompleter(cmds);
        }
        Bukkit.getScheduler().runTaskTimer(this, this::tick, 20L, 20L);
        for (Player p : Bukkit.getOnlinePlayers()) auth.begin(p);
        getLogger().info("RWLogin enabled (BCrypt + SQLite).");
    }

    @Override
    public void onDisable() {
        if (db != null) db.close();
    }

    Component msg(String key, TagResolver... r) {
        return MM.deserialize(getConfig().getString("messages." + key, key), r);
    }

    TagResolver ph(String name, String value) {
        return Placeholder.unparsed(name, value);
    }

    String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    String ip(Player p) {
        return p.getAddress() == null ? "?" : p.getAddress().getAddress().getHostAddress();
    }

    String fmt(long seconds) {
        return String.format("%d:%02d", seconds / 60, seconds % 60);
    }

    void sync(Runnable r) {
        if (isEnabled()) Bukkit.getScheduler().runTask(this, r);
    }

    boolean isAuthed(Player p) {
        return authed.contains(p.getUniqueId());
    }

    /** Called on the main thread when the password check succeeded. */
    void success(Player p, String messageKey) {
        if (!p.isOnline()) return;
        authed.add(p.getUniqueId());
        try {
            p.closeDialog();
        } catch (Throwable ignored) {
        }
        p.sendMessage(msg(messageKey));
    }

    private void tick() {
        long limit = getConfig().getLong("security.login-timeout-seconds", 120) * 1000L;
        long now = System.currentTimeMillis();
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (isAuthed(p)) continue;
            long t = joinAt.getOrDefault(p.getUniqueId(), now);
            if (now - t > limit) {
                p.kick(msg("timeout-kick"));
            } else {
                p.sendActionBar(msg(auth.isRegistered(p) ? "hint-login" : "hint-register"));
            }
        }
    }
          }
