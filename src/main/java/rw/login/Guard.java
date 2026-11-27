package rw.login;

import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.entity.Entity;
import org.bukkit.entity.Player;
import org.bukkit.event.Cancellable;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.EntityTargetLivingEntityEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;

import java.util.Locale;
import java.util.Set;

/** Join/quit handling and the server-side lock for players who are not logged in. */
final class Guard implements Listener {
    private static final Set<String> ALLOWED = Set.of("login", "l", "register", "reg");
    private final RWLogin pl;

    Guard(RWLogin pl) {
        this.pl = pl;
    }

    private boolean locked(Entity e) {
        return e instanceof Player p && !pl.isAuthed(p);
    }

    private void deny(Cancellable e, Entity who) {
        if (locked(who)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        String name = e.getName();
        if (!name.matches(pl.getConfig().getString("name-regex", "^[A-Za-z0-9_]{3,16}$"))) {
            e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, pl.msg("invalid-name"));
            return;
        }
        long ipWait = pl.ips.blockedFor(e.getAddress().getHostAddress());
        if (ipWait > 0) {
            e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, pl.msg("ip-locked", pl.ph("time", pl.fmt(ipWait))));
            return;
        }
        Player online = pl.getServer().getPlayerExact(name);
        if (online != null && online.getAddress() != null
                && !online.getAddress().getAddress().getHostAddress().equals(e.getAddress().getHostAddress())) {
            e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    pl.msg("already-online"));
            return;
        }
        try {
            String key = pl.key(name);
            Db.Account a = pl.db.query(() -> pl.db.find(key));
            long now = System.currentTimeMillis();
            if (a != null && a.lockedUntil() > now) {
                long left = (a.lockedUntil() - now + 999) / 1000;
                e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, pl.msg("locked-join", pl.ph("time", pl.fmt(left))));
            }
        } catch (Exception ignored) {
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent e) {
        pl.auth.begin(e.getPlayer());
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        pl.auth.quit(e.getPlayer());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCmd(PlayerCommandPreprocessEvent e) {
        if (pl.isAuthed(e.getPlayer())) return;
        String m = e.getMessage().toLowerCase(Locale.ROOT).trim();
        if (m.startsWith("/")) m = m.substring(1);
        String head = m.split("\\s+")[0];
        int i = head.indexOf(':');
        if (i >= 0) head = head.substring(i + 1);
        if (!ALLOWED.contains(head)) {
            e.setCancelled(true);
            e.getPlayer().sendMessage(pl.msg("not-authed"));
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onMove(PlayerMoveEvent e) {
        if (locked(e.getPlayer()) && e.hasChangedPosition()) e.setCancelled(true);
    }

    @EventHandler(ignoreCancelled = true)
    public void onChat(AsyncChatEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onBreak(BlockBreakEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onSwap(PlayerSwapHandItemsEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent e) {
        deny(e, e.getEntity());
    }

    @EventHandler(ignoreCancelled = true)
    public void onInvOpen(InventoryOpenEvent e) {
        deny(e, e.getPlayer());
    }

    @EventHandler(ignoreCancelled = true)
    public void onInvClick(InventoryClickEvent e) {
        deny(e, e.getWhoClicked());
    }

    @EventHandler(ignoreCancelled = true)
    public void onDamage(EntityDamageEvent e) {
        deny(e, e.getEntity());
    }

    @EventHandler(ignoreCancelled = true)
    public void onHit(EntityDamageByEntityEvent e) {
        deny(e, e.getDamager());
    }

    @EventHandler(ignoreCancelled = true)
    public void onFood(FoodLevelChangeEvent e) {
        deny(e, e.getEntity());
    }

    @EventHandler(ignoreCancelled = true)
    public void onTarget(EntityTargetLivingEntityEvent e) {
        if (e.getTarget() != null) deny(e, e.getTarget());
    }
}
