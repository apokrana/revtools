import idc
import idaapi
import idautils
import ida_kernwin

from PySide6 import QtWidgets, QtCore, QtGui
from PySide6.QtCore import Qt

PLUGIN_NAME    = "Dayz Script Method Namer"
PLUGIN_HOTKEY  = "Shift+Alt+N"
PLUGIN_VERSION = "1.0"


def get_cstr(ea):
    if not ea or ea == idc.BADADDR:
        return None
    s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    if not s:
        return None
    try:
        return s.decode("utf-8")
    except Exception:
        return s.decode("latin-1", errors="replace")

def is_identifier(s):
    return bool(s) and len(s) >= 2 and " " not in s and s.replace("_","").isalnum()

def is_code(ea):
    if not ea or ea == idc.BADADDR:
        return False
    return idaapi.getseg(ea) is not None

def reg_before(ref_ea, reg, lookback=40):
    reg = reg.lower()
    ea  = ref_ea
    for _ in range(lookback):
        ea = idc.prev_head(ea)
        if ea == idc.BADADDR:
            return None
        m = idc.print_insn_mnem(ea).lower()
        if m in ("lea","mov") and idc.print_operand(ea, 0).lower() == reg:
            return idc.get_operand_value(ea, 1)
    return None

def expand_register_fns(func, seed):
    found = set(seed)
    ea = func.start_ea
    while ea < func.end_ea and ea != idc.BADADDR:
        if idc.print_insn_mnem(ea).lower() == "call":
            callee = idc.get_operand_value(ea, 0)
            if callee and callee != idc.BADADDR and callee not in found:
                r8v = reg_before(ea, "r8", 20)
                r9v = reg_before(ea, "r9", 20)
                if r8v and r9v:
                    s = get_cstr(r8v)
                    if s and is_identifier(s) and is_code(r9v):
                        found.add(callee)
        ea = idc.next_head(ea)
    return found

_EPILOGUE = {"pop","add","sub","nop","retn","ret","mov","lea","xor","and",
             "or","test","cmp","push"}

def find_tail_jmp(func):
    ea = func.end_ea
    for _ in range(24):
        ea = idc.prev_head(ea)
        if ea == idc.BADADDR or ea < func.start_ea:
            break
        m = idc.print_insn_mnem(ea).lower()
        if m == "jmp":
            tgt = idc.get_operand_value(ea, 0)
            if tgt and tgt != idc.BADADDR and tgt != func.start_ea:
                if not (func.start_ea <= tgt < func.end_ea):
                    return ea, tgt
            break
        if m not in _EPILOGUE:
            break
    return idc.BADADDR, idc.BADADDR

def get_class_name_from_func(func, reg_eas):
    jmp_ea, jmp_tgt = find_tail_jmp(func)
    if jmp_ea != idc.BADADDR:
        v = reg_before(jmp_ea, "rdx", 30)
        if v:
            s = get_cstr(v)
            if s and is_identifier(s):
                return s, jmp_tgt
    ea = func.start_ea
    while ea < func.end_ea and ea != idc.BADADDR:
        if idc.print_insn_mnem(ea).lower() == "call":
            callee = idc.get_operand_value(ea, 0)
            if callee not in reg_eas:
                v = reg_before(ea, "r8", 20)
                if v:
                    s = get_cstr(v)
                    if s and is_identifier(s):
                        return s, idc.BADADDR
        ea = idc.next_head(ea)
    return None, idc.BADADDR

def get_class_name_from_callsites(func_ea):
    candidates = []
    seen = set()
    for xref in idautils.CodeRefsTo(func_ea, True):
        v = reg_before(xref, "rdx", 30)
        if v and v not in seen:
            seen.add(v)
            s = get_cstr(v)
            if s and is_identifier(s):
                candidates.append(s)
    return candidates

def harvest_methods(func, reg_eas):
    results   = []
    seen_impl = set()
    ea = func.start_ea
    while ea < func.end_ea and ea != idc.BADADDR:
        if idc.print_insn_mnem(ea).lower() == "call":
            if idc.get_operand_value(ea, 0) in reg_eas:
                r8v = reg_before(ea, "r8", 30)
                r9v = reg_before(ea, "r9", 30)
                name = get_cstr(r8v) if r8v else None
                if name and r9v and is_code(r9v) and r9v not in seen_impl:
                    seen_impl.add(r9v)
                    results.append((r9v, name))
        ea = idc.next_head(ea)
    return results

def run_rename(force_rename: bool, log_fn):
    """
    Core driver. Calls log_fn(str) for each output line.
    Returns (renamed, skipped).
    """
    register_ea = idc.get_name_ea_simple("ScriptContext_RegisterMethod")
    if register_ea == idc.BADADDR:
        log_fn("[!] ScriptContext_RegisterMethod not found – rename it first.")
        return 0, 0

    log_fn(f"[+] ScriptContext_RegisterMethod @ 0x{register_ea:X}")

    init_starts = set()
    for xref in idautils.CodeRefsTo(register_ea, False):
        fn = idaapi.get_func(xref)
        if fn:
            init_starts.add(fn.start_ea)

    log_fn(f"[+] {len(init_starts)} function(s) call RegisterMethod directly\n")

    class_map = {}
    pending   = set()

    for fs in sorted(init_starts):
        func = idaapi.get_func(fs)
        if not func:
            continue
        reg_eas = expand_register_fns(func, {register_ea})
        name, helper_tgt = get_class_name_from_func(func, reg_eas)
        if name:
            class_map[fs] = name
            if helper_tgt and helper_tgt != idc.BADADDR:
                htgt_func = idaapi.get_func(helper_tgt)
                if htgt_func and htgt_func.start_ea not in class_map:
                    class_map[htgt_func.start_ea] = name
        else:
            pending.add(fs)

    for fs in sorted(pending):
        candidates = get_class_name_from_callsites(fs)
        unique = list(dict.fromkeys(candidates))
        if len(unique) == 1:
            class_map[fs] = unique[0]
        elif len(unique) > 1:
            log_fn(f"[?] 0x{fs:X} – ambiguous class names: "
                   f"{unique[:6]}{'...' if len(unique)>6 else ''}")
        else:
            log_fn(f"[?] 0x{fs:X} – could not determine class name")

    log_fn(f"[+] {len(class_map)} function(s) with resolved class names\n")

    renamed   = 0
    skipped   = 0
    done_impl = set()

    for fs in sorted(class_map):
        func = idaapi.get_func(fs)
        if not func:
            continue
        class_name = class_map[fs]
        reg_eas    = expand_register_fns(func, {register_ea})
        methods    = harvest_methods(func, reg_eas)
        if not methods:
            continue

        log_fn(f"[*] 0x{fs:X}  →  class '{class_name}'")

        for impl_ea, method_name in methods:
            if impl_ea in done_impl:
                continue
            done_impl.add(impl_ea)

            new_name = f"{class_name}::{method_name}"
            old_name = idc.get_func_name(impl_ea) or ""

            if not old_name:
                log_fn(f"    [!] No function at 0x{impl_ea:X} for '{new_name}'")
                skipped += 1
                continue

            already_named = not old_name.startswith("sub_")

            if already_named and not force_rename:
                log_fn(f"    [~] 0x{impl_ea:X}  already '{old_name}'  "
                       f"(wanted '{new_name}')")
                skipped += 1
                continue

            ok = idaapi.set_name(impl_ea, new_name,
                                 idaapi.SN_NOWARN | idaapi.SN_FORCE)
            if ok:
                if old_name != new_name:
                    log_fn(f"    [+] 0x{impl_ea:X}  {old_name}  →  {new_name}")
                renamed += 1
            else:
                log_fn(f"    [!] FAILED  0x{impl_ea:X}  →  {new_name}")
                skipped += 1

    return renamed, skipped


class NamerDialog(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Script Method Namer  v{PLUGIN_VERSION}")
        self.setMinimumWidth(720)
        self.setMinimumHeight(540)
        self.resize(820, 600)
        self._build_ui()

    def _build_ui(self):
        root = QtWidgets.QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(10, 10, 10, 10)

        hdr = QtWidgets.QLabel(
            "<b>ScriptContext_RegisterMethod</b> function auto-renamer")
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(hdr)

        root.addWidget(self._hline())

        opt_box = QtWidgets.QGroupBox("Options")
        opt_lay = QtWidgets.QVBoxLayout(opt_box)

        self.chk_force = QtWidgets.QCheckBox(
            "Force rename  (overwrite already-named functions)")
        self.chk_force.setToolTip(
            "When checked, functions that already have a non-sub_ name\n"
            "will be overwritten with ClassName::MethodName.\n"
            "When unchecked, only sub_XXXXXXXX stubs are renamed.")
        opt_lay.addWidget(self.chk_force)

        root.addWidget(opt_box)

        log_label = QtWidgets.QLabel("Output:")
        root.addWidget(log_label)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        self.log.setFont(QtGui.QFont("Consolas", 9))
        self.log.setMinimumHeight(340)
        root.addWidget(self.log)

        self.status = QtWidgets.QLabel("Ready.")
        self.status.setAlignment(Qt.AlignmentFlag.AlignLeft)
        root.addWidget(self.status)

        root.addWidget(self._hline())

        btn_row = QtWidgets.QHBoxLayout()

        self.btn_run = QtWidgets.QPushButton("▶  Run")
        self.btn_run.setDefault(True)
        self.btn_run.setMinimumHeight(32)
        self.btn_run.setToolTip(f"Hotkey: {PLUGIN_HOTKEY}")

        self.btn_clear = QtWidgets.QPushButton("Clear log")
        self.btn_clear.setMinimumHeight(32)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.setMinimumHeight(32)

        btn_row.addWidget(self.btn_run)
        btn_row.addWidget(self.btn_clear)
        btn_row.addStretch()
        btn_row.addWidget(btn_close)
        root.addLayout(btn_row)

        self.btn_run.clicked.connect(self._on_run)
        self.btn_clear.clicked.connect(self.log.clear)
        btn_close.clicked.connect(self.close)

    @staticmethod
    def _hline():
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        return line

    def _append(self, text: str):
        self.log.appendPlainText(text)
        # keep scroll at bottom
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())
        QtWidgets.QApplication.processEvents()

    def _on_run(self):
        self.log.clear()
        self.btn_run.setEnabled(False)
        self.status.setText("Running…")
        QtWidgets.QApplication.processEvents()

        force = self.chk_force.isChecked()

        try:
            renamed, skipped = run_rename(force_rename=force,
                                          log_fn=self._append)
            summary = (f"Done.  Renamed: {renamed}  |  "
                       f"Skipped/failed: {skipped}  |  "
                       f"Force-rename: {'ON' if force else 'OFF'}")
            self._append(f"\n[+] {summary}")
            self.status.setText(summary)
        except Exception as exc:
            msg = f"[!] Exception: {exc}"
            self._append(msg)
            self.status.setText(msg)
            import traceback
            self._append(traceback.format_exc())
        finally:
            self.btn_run.setEnabled(True)

class ScriptNamerPlugin(idaapi.plugin_t):
    flags       = idaapi.PLUGIN_KEEP
    comment     = "Rename ScriptContext_RegisterMethod implementations"
    help        = f"Press {PLUGIN_HOTKEY} to open the rename dialog"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[ScriptNamer] loaded – press {PLUGIN_HOTKEY} to open")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        parent = QtWidgets.QApplication.activeWindow()
        dlg = NamerDialog(parent)
        dlg.setWindowFlag(Qt.WindowType.Window)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ScriptNamerPlugin()