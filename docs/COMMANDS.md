# Chat commands

[繁體中文](COMMANDS_zh-tw.md)

In a connected topic, anything you type goes to the AI. A command is `!` and one English word, nothing more; the full-width `！` a Chinese keyboard types works too, and a capital letter a phone keyboard adds (`!Status`) does not matter. A message that is only the command (and a permission code) may also end with `。`, `!` or `?`, have a space after the `!`, or be typed in full-width letters: `!stop。`, `! status`, `!ｏｋ　１２３４`. `!help` lists the common ones, and `!help stauts` explains the command a typo meant.

While OpenCode is working, a new message reaches the running reply: OpenCode reads it at its next step, as when you type to Claude Code while it works. Several messages go in order, one after another. If a message cannot join right then (OpenCode is waiting for a permission, something else is queued, or the session changed just as it was sent), it waits until the running reply is done and starts its own reply; it is never lost. Messages with files, schedules, and messages that were paused (`!stop`, then `!go`) always wait and start their own reply. When OpenCode is not working, a message starts a new reply right away. `!status` shows what is waiting; `!stop` stops the running reply and the waiting messages.

Use a topic with a name. Zulip's “general chat” has no topic name, so Bridge only answers there with a reminder to switch topics. When Bridge cannot handle an ordinary message, it says so with a short reason and points to `!status` instead of staying silent.

## When Bridge asks you

| Command | What it does |
| --- | --- |
| `!ok` | Yes to what Bridge just asked you: a schedule, an Agent switch, a fork, compaction, a rollback, Git, reconnecting after OpenCode restarted (one `!ok` is enough) |
| `!no` | No. Drops everything Bridge asked you and you have not answered, and your messages not sent yet. Nothing is sent |
| `!ok 1234` / `!no 1234 reason` | Answers an OpenCode permission request; the code is in the notice |
| `!a 1234 answer` | Answers the AI's question |
| `!1`, `!2`… | Picks a menu item; `!next` shows the next page |
| `!pending` | Lists permissions and questions waiting for you |

On desktop (the app and the web) these questions, the paused notices (`!go` / `!no`, `!ok` to reconnect), the "continue" after `!stop` and schedule offers have buttons under them; a click sends that command. The phone app shows no buttons, so type the command the message names.

## Control

| Command | What it does |
| --- | --- |
| `!stop` | Stops everything: interrupts the current work, pauses queued messages and stops your schedules here. After the stop, just type a new message to continue; `!go` / `!no` are only for messages queued before the stop |
| `!go` | Continues: resumes the paused queue and sends messages not sent yet; while a new conversation is still being created, connects it to this topic |
| `!go new` | Sends only the new: drops your unsent messages from an hour or more ago and sends the rest in order. While a topic still holds a message that old, a new message never carries it along by itself; it stops and lets you pick `!go new` / `!go` / `!no` (buttons on desktop) |
| `!status` | Current state (while a reply runs, whether it waits on a tool, named, or on the model) and queued messages (numbered in order, each with its first few words; unsent ones point to `!go` / `!no`, with buttons on desktop; one waiting an hour or more says when it was sent; a waiting permission request is named with its coded `!ok` / `!no`, anything else waiting on you points to `!pending`) |
| `!reconnect` | Usually not needed: after OpenCode restarts, Bridge reconnects the conversation by itself and says so in one line. When it could not, the topic says so in one line and a plain `!ok` reconnects (on desktop, the button does the same); `!reconnect` first shows the details, then `!ok` confirms them. Messages sent meanwhile then go in order, and only a topic you stopped yourself still needs `!go`; the paused notice and `!status` point to it |

### When Bridge restarts

A Bridge restart does not stop a topic. Messages you sent in the last 10 minutes, including ones sent while Bridge was offline, are sent by themselves when it is back. If older messages are waiting, nothing is sent and Bridge replies once: `!go` sends them in order, `!no` drops them. Messages sent while it was offline that are older or were edited are not sent; Bridge says so once, so send them again if you still need them. A pause you chose (`!stop`, `!oz queue pause` or an administrator's) stays until someone resumes it; in such an already paused topic, messages sent while Bridge was offline are still picked up and answered once with how to continue (`!go` / `!no`), never left silent.

A message that cannot be sent as written (for example, it was edited or can no longer be confirmed) is not sent, and Bridge says so once; it does not stop the messages after it. If OpenCode is briefly unreachable, Bridge keeps trying for a few minutes before it gives up on a message and says so.

## Conversation

| Command | What it does |
| --- | --- |
| `!go`, `!go keyword` | Picks an existing conversation in a topic that is not connected yet |
| `!new` | Starts a new conversation; choose a project, optionally add a title |
| `!disconnect` | Disconnects this topic; the conversation stays in OpenCode |
| `!model` | Changes the model |
| `!agent` | Changes the Agent |
| `!rename title` | Renames the conversation |
| `!fork` | Branches a new conversation off here, then `!ok` |
| `!compact` | Compacts the conversation, then `!ok` |
| `!undo` | Rolls back to before a message (pick it, then `!ok`) |
| `!redo` | Brings rolled-back messages back |
| `!discard` | Deletes rolled-back messages for good |
| `!archive` / `!unarchive` | Archives / unarchives |

## Reading

| Command | What it does |
| --- | --- |
| `!history` | Earlier messages |
| `!output` | The latest reply in full, in pages |
| `!files`, `!file path` | Finds files, downloads a file |
| `!diff` | Which files this turn changed |
| `!export` | Exports the conversation |

## More

| Command | What it does |
| --- | --- |
| “every 30 minutes … until 18:00” | Sets a schedule in plain words. Bridge shows what it understood; `!ok` starts it, `!send` sends it once as written, `!no` drops it |
| `!schedule` | Lists this topic's schedules; `!stop` stops them |
| `!commit message`, `!push` | Git commit / push: a preview first, then `!ok` (when enabled) |
| `!send text` | Sends text exactly as written, even text that starts with `!` |
| `ok` / `no` without `!` | While a question waits on you here (a confirmation, a permission, a reconnect), Bridge asks whether you meant `!ok` / `!no` instead of passing the word to the AI; `!send ok` sends it to the AI. For a single permission request it names `!ok 1234` / `!no 1234` with that request's code, and the desktop buttons carry the code too; with several requests waiting it points to `!pending`. When what waits is the AI's own question, it points to `!pending`, which shows the question and how to answer it. A lone `1` or `2` while something waits is read the same way, as picking the first or second button by number. With nothing waiting, it goes to the AI as usual |
| A mistyped command such as `!stauts` | In a connected topic, a word one slip away from an everyday command (two letters swapped; for words of five letters or more, one letter missing, extra or wrong) is not sent to the AI. Bridge asks whether you meant that command, e.g. `!status`; the desktop buttons run it or send your text as written. `!send !stauts` also sends it as written. Other text that starts with `!` still goes to the AI |
| `!steer -- text` | Same as a plain message (it reaches a running reply too), with the text exactly as written and a short note where it went |
| `!lang en` / `!lang zh-TW` / `!lang auto` | Interface language |
| `!help`, `!help command`, `!help all` | Common commands, one command's usage, advanced commands |

## Advanced commands

`!help all` lists the advanced commands, such as `!oz worktree`, `!oz checks`, `!oz recovery`, `!oz outputs` and `!oz git review`, and the `!oz <command> <token>` lines that menu buttons send. Buttons send those for you.

Each everyday word runs one advanced command: `!go` is `!oz queue resume`, `!undo` is `!oz revert`. Both forms go through the same permission and source checks and leave the same records.
