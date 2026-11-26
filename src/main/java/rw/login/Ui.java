package rw.login;

import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickCallback;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.List;

/** Password dialog screen with a safe chat fallback. */
final class Ui {
    private final RWLogin pl;
    private boolean warned;

    Ui(RWLogin pl) {
        this.pl = pl;
    }

    /** Show the register (true) or login (false) screen. Main thread only. */
    void show(Player p, boolean register, Component error) {
        if (!p.isOnline() || pl.isAuthed(p)) return;
        if (pl.getConfig().getBoolean("ui.use-dialog", true)) {
            try {
                p.showDialog(build(p, register, error));
                return;
            } catch (Throwable t) {
                if (!warned) {
                    warned = true;
                    pl.getLogger().warning("Dialog API unavailable, using chat fallback: " + t);
                }
            }
        }
        p.sendMessage(pl.msg(register ? "hint-register" : "hint-login"));
        if (error != null) p.sendMessage(error);
    }

    private Dialog build(Player p, boolean register, Component error) {
        var player = pl.ph("player", p.getName());
        var min = pl.ph("min", String.valueOf(pl.getConfig().getInt("password.min-length", 6)));
        var max = pl.ph("max", String.valueOf(pl.getConfig().getInt("password.max-length", 32)));
        List<DialogBody> body = new ArrayList<>();
        String raw = pl.getConfig().getString(register ? "messages.body-register" : "messages.body-login", "");
        for (String line : raw.split("\\n")) {
            body.add(DialogBody.plainMessage(RWLogin.MM.deserialize(line, player, min, max)));
        }
        if (error != null) body.add(DialogBody.plainMessage(error));
        List<DialogInput> inputs = new ArrayList<>();
        inputs.add(DialogInput.text("pw", pl.msg("label-password")).width(300).build());
        if (register) inputs.add(DialogInput.text("pw2", pl.msg("label-confirm")).width(300).build());
        ClickCallback.Options once = ClickCallback.Options.builder().uses(1).build();
        ActionButton submit = ActionButton.create(pl.msg(register ? "btn-register" : "btn-login"), null, 200,
                DialogAction.customClick((view, audience) -> {
                    String a = view.getText("pw");
                    String b = register ? view.getText("pw2") : null;
                    Bukkit.getScheduler().runTask(pl, () -> {
                        if (register) pl.reg.register(p, a, b);
                        else pl.auth.login(p, a);
                    });
                }, once));
        ActionButton logout = ActionButton.create(pl.msg("btn-logout"), null, 150,
                DialogAction.customClick((view, audience) ->
                        Bukkit.getScheduler().runTask(pl, () -> p.kick(pl.msg("logout-kick"))), once));
        return Dialog.create(f -> f.empty()
                .base(DialogBase.builder(pl.msg(register ? "title-register" : "title-login"))
                        .canCloseWithEscape(false)
                        .body(body)
                        .inputs(inputs)
                        .build())
                .type(DialogType.multiAction(List.of(submit), logout, 1)));
    }
          }
