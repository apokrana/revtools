import idaapi
import idautils
import idc
from collections import defaultdict

HOTKEY    = "Ctrl+Alt+F"
BANNER    = "=" * 60
DIVIDER   = "-" * 60

def _call_sites(ea: int) -> list[int]:
    """Return addresses of every instruction that *calls* ea."""
    return [
        ref.frm
        for ref in idautils.XrefsTo(ea, idaapi.XREF_ALL)
        if idc.print_insn_mnem(ref.frm) == "call"
    ]


def _parent_func(ea: int):
    """Return the start EA of the function containing ea, or None."""
    f = idaapi.get_func(ea)
    return f.start_ea if f else None


def _group_by_parent(call_sites: list[int]) -> dict:
    groups = defaultdict(list)
    for site in call_sites:
        pf = _parent_func(site)
        if pf is not None:
            groups[pf].append(site)
    return groups


def run_analysis(addr_a: int, addr_b: int, threshold: int) -> None:
    name_a = idc.get_name(addr_a) or hex(addr_a)
    name_b = idc.get_name(addr_b) or hex(addr_b)

    print(f"\n{BANNER}")
    print(f"  XRef Proximity Finder")
    print(BANNER)
    print(f"  Target A : {hex(addr_a)}  ({name_a})")
    print(f"  Target B : {hex(addr_b)}  ({name_b})")
    print(f"  Distance : ≤ {threshold} bytes")
    print(DIVIDER)

    sites_a = _group_by_parent(_call_sites(addr_a))
    sites_b = _group_by_parent(_call_sites(addr_b))

    print(f"  Callers of A : {sum(len(v) for v in sites_a.values())} call site(s)"
          f" in {len(sites_a)} function(s)")
    print(f"  Callers of B : {sum(len(v) for v in sites_b.values())} call site(s)"
          f" in {len(sites_b)} function(s)")

    common = set(sites_a) & set(sites_b)
    print(f"  Shared funcs : {len(common)}")
    print(DIVIDER)

    if not common:
        print("  [!] No functions call both targets.")
        print(BANNER)
        return

    hits = []
    closest: dict[int, tuple] = {}

    for pf in common:
        for ca in sites_a[pf]:
            for cb in sites_b[pf]:
                dist = abs(ca - cb)
                if dist <= threshold:
                    hits.append((pf, ca, cb, dist))
                # Track closest pair per parent regardless of threshold
                prev = closest.get(pf)
                if prev is None or dist < prev[0]:
                    closest[pf] = (dist, ca, cb)

    if hits:
        # Sort by distance (tightest first)
        hits.sort(key=lambda x: x[3])
        print(f"  [+] {len(hits)} match(es) within {threshold} bytes\n")
        for pf, ca, cb, dist in hits:
            fn = idc.get_func_name(pf) or "???"
            order = ("A → B", "B → A")[cb < ca]
            print(f"  MATCH  {hex(pf)}  {fn}")
            print(f"         Call A  @ {hex(ca)}")
            print(f"         Call B  @ {hex(cb)}")
            print(f"         Order   : {order}")
            print(f"         Distance: {dist} byte(s)")
            print()
    else:
        print(f"  [-] No matches within {threshold} bytes.\n")
        print("  Closest pairs per shared function:")
        print()
        rows = sorted(closest.items(), key=lambda kv: kv[1][0])
        for pf, (dist, ca, cb) in rows:
            fn = idc.get_func_name(pf) or "???"
            print(f"    {hex(pf)}  {fn}")
            print(f"      Call A @ {hex(ca)}   Call B @ {hex(cb)}   dist={dist}")
            print()

    print(BANNER)

class XRefFinderForm(idaapi.Form):
    """Simple modal form with two address fields and a threshold spinner."""

    def __init__(self):
        self.invert = False
        form_spec = r"""STARTITEM 0
XRef Proximity Finder

  <Target A (hex address):{iAddrA}>
  <Target B (hex address):{iAddrB}>
  <Max distance (bytes)  :{iThresh}>
"""
        controls = {
            "iAddrA":  idaapi.Form.StringInput(swidth=20),
            "iAddrB":  idaapi.Form.StringInput(swidth=20),
            "iThresh": idaapi.Form.StringInput(swidth=10),
        }
        idaapi.Form.__init__(self, form_spec, controls)

    @staticmethod
    def _parse_addr(raw: str) -> int | None:
        raw = raw.strip().lower().replace("0x", "")
        try:
            return int(raw, 16)
        except ValueError:
            return None

    @staticmethod
    def _parse_threshold(raw: str) -> int:
        try:
            v = int(raw.strip())
            return v if v > 0 else 100
        except ValueError:
            return 100

    def show(self) -> bool:
        """Compile, display, and return True if OK was pressed."""
        self.Compile()
        self.iAddrA.value  = ""
        self.iAddrB.value  = ""
        self.iThresh.value = "100"
        ok = self.Execute()
        if ok != 1:
            return False

        addr_a = self._parse_addr(self.iAddrA.value)
        addr_b = self._parse_addr(self.iAddrB.value)

        if addr_a is None or addr_b is None:
            idaapi.warning("Invalid address — enter hex values (e.g. 1405B39F0).")
            return False

        if addr_a == addr_b:
            idaapi.warning("Targets must be different addresses.")
            return False

        threshold = self._parse_threshold(self.iThresh.value)
        run_analysis(addr_a, addr_b, threshold)
        return True

    def Free(self):
        idaapi.Form.Free(self)



class XRefFinderPlugin(idaapi.plugin_t):
    flags        = idaapi.PLUGIN_UNL  
    comment      = "Find functions calling two targets within N bytes"
    help         = "Ctrl+Alt+F to open"
    wanted_name  = "XRef Proximity Finder"
    wanted_hotkey = ""  

    def init(self):
        self._hotkey = idaapi.add_hotkey(HOTKEY, self._on_hotkey)
        if self._hotkey:
            print(f"[XRefFinder] Loaded — press {HOTKEY} to open")
        else:
            print(f"[XRefFinder] Loaded — could not register {HOTKEY} (conflict?)")
        return idaapi.PLUGIN_KEEP

    def run(self, _arg):
        self._open_dialog()

    def term(self):
        if self._hotkey:
            idaapi.del_hotkey(self._hotkey)

    @staticmethod
    def _on_hotkey():
        form = XRefFinderForm()
        try:
            form.show()
        finally:
            form.Free()

    @classmethod
    def _open_dialog(cls):
        cls._on_hotkey()


def PLUGIN_ENTRY():
    return XRefFinderPlugin()

if __name__ == "__main__":
    form = XRefFinderForm()
    try:
        form.show()
    finally:
        form.Free()