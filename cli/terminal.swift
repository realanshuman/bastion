// terminal.swift: the `bastion` command in new terminal windows. Setting it up changes your shell setup (or adds a
// link to a folder already on your PATH), so Bastion always works out the exact change first, shows it, and makes it
// only after a yes. Removing it takes out exactly what Bastion added, and nothing it didn't.
import Foundation

let CLI_MARK_A = "# >>> bastion command line >>>"
let CLI_MARK_B = "# <<< bastion command line <<<"

/// The command a terminal should run: the engine's copy, which the app keeps up to date
var ourCommand: String { engine("bin/bastion") }

/// Bastion's folder as a shell sees it: through $HOME when it's in the usual place, so the line reads the same everywhere
var binRef: String { ENGINE == HOME + "/.security-guard" ? "$HOME/.security-guard/bin" : engine("bin") }

/// Your user folders that are often already on PATH. Bastion only ever adds a link here, never to system folders.
var linkDirs: [String] { [HOME + "/.local/bin", HOME + "/bin"] }

struct LoginShell { let name: String; let path: String }

/// $SHELL, else the shell in your user record
func loginShell() -> LoginShell {
    let env = ProcessInfo.processInfo.environment["SHELL"].flatMap { $0.isEmpty ? nil : $0 }
    let record = getpwuid(getuid()).flatMap { $0.pointee.pw_shell }.map { String(cString: $0) }
    let path = env ?? record ?? "/bin/zsh"
    return LoginShell(name: (path as NSString).lastPathComponent, path: path)
}

/// Exists, without following a symlink (a broken link still counts)
func lexists(_ path: String) -> Bool { var st = stat(); return lstat(path, &st) == 0 }

func isSymlink(_ path: String) -> Bool { (try? fm.destinationOfSymbolicLink(atPath: path)) != nil }

/// A link Bastion could have made: it points at the engine's command
func isOurLink(_ path: String) -> Bool {
    guard let dest = try? fm.destinationOfSymbolicLink(atPath: path) else { return false }
    let full = dest.hasPrefix("/") ? dest : ((path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(dest)
    return canon(full) == canon(ourCommand)
}

func firstExecutable(_ name: String, in dirs: [String]) -> String? {
    dirs.lazy.map { ($0 as NSString).appendingPathComponent(name) }.first { p in
        var dir: ObjCBool = false
        return fm.fileExists(atPath: p, isDirectory: &dir) && !dir.boolValue && fm.isExecutableFile(atPath: p)
    }
}

// MARK: - What a new terminal window sees

struct ShellProbe { let path: [String]; let configDir: String? }

/// Starts your login shell the way a terminal window does (its startup files included) and reads its PATH and where
/// it keeps its setup. nil if the shell doesn't answer within a few seconds.
func probeShell(_ sh: LoginShell) -> ShellProbe? {
    let m = "__BASTION_PROBE__"
    let script: String
    switch sh.name {
    case "fish": script = "printf '\\n\(m)%s\\n\(m)%s\\n' (string join : $PATH) $__fish_config_dir"
    case "zsh": script = "printf '\\n\(m)%s\\n\(m)%s\\n' \"$PATH\" \"${ZDOTDIR:-$HOME}\""
    default: script = "printf '\\n\(m)%s\\n\(m)%s\\n' \"$PATH\" \"$HOME\""
    }
    // a terminal window starts from the Mac's basic PATH; the shell's own startup files add the rest
    let r = run(sh.path, ["-i", "-l", "-c", script], timeout: 8, env: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"])
    let found = r.out.components(separatedBy: "\n").filter { $0.hasPrefix(m) }.map { String($0.dropFirst(m.count)) }
    guard found.count >= 2 else { return nil }
    let path = found[found.count - 2].split(separator: ":").map(String.init).filter { !$0.isEmpty }
    let dir = found[found.count - 1]
    return ShellProbe(path: path, configDir: dir.isEmpty ? nil : dir)
}

/// The file each shell reads when a terminal window opens, and the lines that put Bastion's folder at the END of PATH
/// (last, so it can never stand in for another command)
func shellSetup(_ sh: LoginShell, configDir: String?) -> (file: String, lines: [String])? {
    let posix = [CLI_MARK_A, "export PATH=\"$PATH:\(binRef)\"", CLI_MARK_B]
    switch sh.name {
    case "zsh":
        return ((configDir ?? HOME) + "/.zshrc", posix)
    case "bash":   // a login shell reads the first of these that exists; creating .bash_profile would hide .profile
        let file = [".bash_profile", ".bash_login", ".profile"].map { HOME + "/" + $0 }.first { fm.fileExists(atPath: $0) }
        return (file ?? HOME + "/.bash_profile", posix)
    case "sh", "ksh":
        return (HOME + "/.profile", posix)
    case "fish":   // a file of its own in conf.d: config.fish stays untouched
        return ((configDir ?? HOME + "/.config/fish") + "/conf.d/bastion.fish",
                [CLI_MARK_A, "if not contains \(binRef) $PATH", "    set -gx PATH $PATH \(binRef)", "end", CLI_MARK_B])
    default:
        return nil
    }
}

// MARK: - Is it set up?

/// Where Bastion may have written its lines: the shell file it recorded, then the usual places
func blockFiles() -> [String] {
    var files: [String] = []
    if let rec = settings()["command_line"] as? [String: Any], rec["how"] as? String == "shell", let w = rec["where"] as? String { files.append(w) }
    files += [".zshrc", ".bash_profile", ".bash_login", ".profile", ".config/fish/conf.d/bastion.fish"].map { HOME + "/" + $0 }
    var seen = Set<String>()
    return files.filter { seen.insert(canon($0)).inserted }
}

/// A small text file (a shell's startup file), read. nil for anything else: a program, a folder, a huge file.
func shellText(_ file: String) -> String? {
    guard !isOurLink(file), let d = fm.contents(atPath: file), d.count < 1_000_000 else { return nil }
    return String(data: d, encoding: .utf8)
}

/// Bastion's block, as whole lines of a shell file (a program that only contains the words doesn't count)
func hasBlock(_ file: String) -> Bool { shellText(file)?.components(separatedBy: "\n").contains(CLI_MARK_A) ?? false }

/// Startup files a person might have edited by hand
func manualFiles() -> [String] {
    [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".bash_login", ".profile", ".config/fish/config.fish"].map { HOME + "/" + $0 }
}

/// Only the lines Bastion added, never the rest of the file
func withoutBlock(_ text: String) -> String {
    var lines = text.components(separatedBy: "\n")
    while let a = lines.firstIndex(of: CLI_MARK_A) {
        let b = lines[a...].firstIndex(of: CLI_MARK_B) ?? a
        let atEnd = lines[(b + 1)...].allSatisfy { $0.isEmpty }
        lines.removeSubrange(a...b)
        // the blank line Bastion put before its block, when the block was the last thing in the file
        if atEnd, a > 0, lines[a - 1].isEmpty, a - 1 < lines.count - 1 { lines.remove(at: a - 1) }
    }
    return lines.joined(separator: "\n")
}

/// installed · how (link, shell, manual or none) · where · ours (everything Bastion itself added)
func commandLineStatus() -> [String: Any] {
    var ours: [[String: String]] = []
    for dir in linkDirs where isOurLink(dir + "/bastion") { ours.append(["how": "link", "where": dir + "/bastion"]) }
    for f in blockFiles() where hasBlock(f) { ours.append(["how": "shell", "where": f]) }
    var out: [String: Any] = ["command": ourCommand, "ours": ours]
    if let first = ours.first {
        out["installed"] = true; out["how"] = first["how"]; out["where"] = first["where"]
        return out
    }
    // set up by hand: a PATH line of your own, or a link somewhere else
    if let f = manualFiles().first(where: { withoutBlock(readText($0)).contains(".security-guard/bin") }) {
        out["installed"] = true; out["how"] = "manual"; out["where"] = f
        return out
    }
    if let l = ["/usr/local/bin/bastion", "/opt/homebrew/bin/bastion"].first(where: isOurLink) {
        out["installed"] = true; out["how"] = "manual"; out["where"] = l
        return out
    }
    out["installed"] = false; out["how"] = "none"
    return out
}

// MARK: - What installing would change

/// action: none (already works) · link · shell · conflict (another bastion comes first) · unsupported (unknown shell)
func commandLinePlan() -> [String: Any] {
    let sh = loginShell()
    let probe = probeShell(sh)
    var out: [String: Any] = ["shell": sh.name, "status": commandLineStatus(), "probed": probe != nil, "command": ourCommand]
    if let probe {
        if let found = firstExecutable("bastion", in: probe.path) {
            out["found"] = found
            if canon(found) == canon(ourCommand) {
                out["action"] = "none"; out["works_now"] = true
                out["summary"] = "bastion already works in new terminal windows."
            } else {
                out["action"] = "conflict"; out["works_now"] = false
                out["summary"] = "Another program called bastion comes first on your PATH, at \(tilde(found)). Bastion won't change anything."
            }
            return out
        }
        // a folder of yours that's already on PATH: a link there works at once, even in open windows
        let onPath = Set(probe.path.map(canon))
        if let dir = linkDirs.first(where: { onPath.contains(canon($0)) && fm.isWritableFile(atPath: $0) && !lexists($0 + "/bastion") }) {
            out["action"] = "link"; out["link"] = dir + "/bastion"; out["works_now"] = false
            out["summary"] = "Bastion will add a link at \(tilde(dir))/bastion. That folder is already on your PATH, so your shell setup doesn't change, and it works in terminal windows that are already open too."
            return out
        }
    }
    guard let setup = shellSetup(sh, configDir: probe?.configDir) else {
        out["action"] = "unsupported"; out["works_now"] = false; out["folder"] = engine("bin")
        out["summary"] = "Bastion can't set this up for \(sh.name). Add \(tilde(engine("bin"))) to your PATH yourself."
        return out
    }
    let exists = fm.fileExists(atPath: setup.file)
    out["action"] = "shell"; out["file"] = setup.file; out["lines"] = setup.lines; out["creates_file"] = !exists; out["works_now"] = false
    out["summary"] = exists
        ? "Bastion will add these \(setup.lines.count) lines to the end of \(tilde(setup.file)), so new terminal windows find the bastion command. Nothing else in the file changes."
        : "Bastion will create \(tilde(setup.file)) with these \(setup.lines.count) lines, so new terminal windows find the bastion command."
    if probe == nil { out["note"] = "Your shell didn't answer in time, so Bastion couldn't check how it starts. The lines above are the usual way." }
    return out
}

// MARK: - Install and remove

private func humanPreview(_ plan: [String: Any]) {
    guard !wantJSON else { return }
    print(plan["summary"] as? String ?? "")
    if let lines = plan["lines"] as? [String] { print(""); lines.forEach { print("    " + $0) }; print("") }
}

/// Appends the block, keeping the file (and a symlinked file's link) in place
private func appendBlock(_ lines: [String], to file: String) throws {
    let real = canon(file)
    try fm.createDirectory(atPath: (real as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    if fm.fileExists(atPath: real) && shellText(real) == nil { throw Failure("\(tilde(file)) doesn't look like a shell file. Nothing changed.") }
    var text = readText(real)
    if !text.isEmpty && !text.hasSuffix("\n") { text += "\n" }
    if !text.isEmpty { text += "\n" }
    text += lines.joined(separator: "\n") + "\n"
    guard (try? text.write(toFile: real, atomically: false, encoding: .utf8)) != nil else { throw Failure("Couldn't write to \(tilde(file)). Nothing changed.") }
}

/// A new terminal window finds the engine's bastion (nil: the shell didn't answer)
func newTerminalFindsUs() -> Bool? {
    guard let probe = probeShell(loginShell()) else { return nil }
    return firstExecutable("bastion", in: probe.path).map { canon($0) == canon(ourCommand) } ?? false
}

func installCommandLine() throws -> [String: Any] {
    try requireEngine()
    guard fm.isExecutableFile(atPath: ourCommand) else { throw Failure("Bastion's command isn't at \(tilde(ourCommand)). Open Bastion.app once so it can set itself up.") }
    let plan = commandLinePlan()
    var r: [String: Any] = ["plan": plan, "changed": false]
    switch plan["action"] as? String ?? "" {
    case "none":
        r["ok"] = true; r["verified"] = true; r["message"] = "bastion already works in new terminal windows. Nothing changed."
        return r
    case "link":
        let link = plan["link"] as? String ?? ""
        humanPreview(plan)
        try confirmWeakening("Add the link?", why: "This adds a file to a folder on your PATH, so a person has to confirm it.")
        do { try fm.createSymbolicLink(atPath: link, withDestinationPath: ourCommand) }
        catch { throw Failure("Couldn't add a link at \(tilde(link)). Nothing changed.") }
        updateSettings { $0["command_line"] = ["how": "link", "where": link] }
        logEvent("CHANGED: linked the bastion command at \(tilde(link))")
        r["how"] = "link"; r["where"] = link
    case "shell":
        let file = plan["file"] as? String ?? "", lines = plan["lines"] as? [String] ?? []
        if hasBlock(file) {
            r["ok"] = true; r["how"] = "shell"; r["where"] = file
            r["verified"] = false; r["message"] = "Bastion's lines are already in \(tilde(file)), but a new terminal window doesn't find bastion. Something later in that file may set PATH again."
            return r
        }
        humanPreview(plan)
        try confirmWeakening(fm.fileExists(atPath: file) ? "Add them to \(tilde(file))?" : "Create \(tilde(file))?",
                             why: "This changes your shell setup, so a person has to confirm it.")
        let created = !fm.fileExists(atPath: file)
        try appendBlock(lines, to: file)
        updateSettings { $0["command_line"] = ["how": "shell", "where": file, "created": created] }
        logEvent("CHANGED: added the bastion command to \(tilde(file))")
        r["how"] = "shell"; r["where"] = file
    default:
        r["ok"] = false; r["message"] = plan["summary"] as? String ?? "Bastion can't set this up here. Nothing changed."
        return r
    }
    r["changed"] = true; r["ok"] = true
    let verified = newTerminalFindsUs()
    if let verified { r["verified"] = verified } else { r["verified"] = NSNull() }
    let place = tilde(r["where"] as? String ?? "")
    let how = r["how"] as? String == "link" ? "Linked at \(place)." : "Added to \(place)."
    switch verified {
    case true?:
        r["message"] = how + (r["how"] as? String == "link" ? " It works now, in any terminal window." : " Open a new terminal window and run: bastion status")
    case false?:
        r["message"] = how + " But a new terminal window still doesn't find bastion. Something later in your shell setup may set PATH again."
    case nil:
        r["message"] = how + " Open a new terminal window and run: bastion status"
    }
    return r
}

func removeCommandLine() throws -> [String: Any] {
    let st = commandLineStatus()
    let ours = st["ours"] as? [[String: String]] ?? []
    if ours.isEmpty {
        if st["how"] as? String == "manual" {
            return ["ok": false, "changed": false, "status": st,
                    "message": "You added bastion to your PATH yourself, in \(tilde(st["where"] as? String ?? "")). Bastion leaves that alone."]
        }
        return ["ok": true, "changed": false, "status": st, "message": "bastion isn't set up in your terminal, so there's nothing to remove."]
    }
    let places = ours.map { tilde($0["where"] ?? "") }.joined(separator: " and ")
    if !wantJSON { print("Bastion will remove what it added: \(places).") }
    try confirmWeakening("Remove it?", why: "This changes your shell setup, so a person has to confirm it.")
    let recorded = settings()["command_line"] as? [String: Any]
    var removed: [String] = []
    for o in ours {
        let path = o["where"] ?? ""
        if o["how"] == "link" {
            if isOurLink(path), (try? fm.removeItem(atPath: path)) != nil { removed.append(path) }
            continue
        }
        let real = canon(path)
        guard hasBlock(real), let text = shellText(real) else { continue }   // only ever a shell file with Bastion's lines in it
        let rest = withoutBlock(text)
        let createdByUs = recorded?["where"] as? String == path && recorded?["created"] as? Bool == true
        if rest.trimmed.isEmpty && (createdByUs || path.hasSuffix("/conf.d/bastion.fish")) {
            if (try? fm.removeItem(atPath: real)) != nil { removed.append(path) }
        } else if (try? rest.write(toFile: real, atomically: false, encoding: .utf8)) != nil {
            removed.append(path)
        }
    }
    updateSettings { $0["command_line"] = nil }
    let gone = removed.map(tilde).joined(separator: " and ")
    if !removed.isEmpty { logEvent("CHANGED: removed the bastion command from \(gone)") }
    var r: [String: Any] = ["ok": removed.count == ours.count, "changed": !removed.isEmpty, "removed": removed]
    let still = removed.isEmpty ? nil : newTerminalFindsUs()
    if let still { r["still_works"] = still } else { r["still_works"] = NSNull() }
    r["message"] = removed.isEmpty ? "Couldn't remove it from \(places). Nothing changed."
        : "Removed from \(gone)." + (still == true ? " A new terminal window still finds bastion through a setup of your own." : " New terminal windows won't find bastion.")
    return r
}
