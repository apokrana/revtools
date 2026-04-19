import idc
import idaapi
import idautils

class DeleteAnteriorLines(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Delete anterior lines in current function"
    help = ""
    wanted_name = "Delete Anterior Lines"
    wanted_hotkey = "Ctrl+Alt+/"   

    def init(self):
        print("[DeleteAnterior] Plugin loaded. Hotkey: %s" % self.wanted_hotkey)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ea = idc.here()
        func = idaapi.get_func(ea)

        if not func:
            print("[DeleteAnterior] Cursor is not inside a function.")
            return

        count = 0
        for addr in idautils.FuncItems(func.start_ea):
            i = 0
            while idc.get_extra_cmt(addr, idc.E_PREV + i) is not None:
                idc.del_extra_cmt(addr, idc.E_PREV + i)
                i += 1
                count += 1

        print("[DeleteAnterior] Removed %d anterior line(s) from function at 0x%X" % (count, func.start_ea))

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DeleteAnteriorLines()

    
def reload_plugin():
    import sys, idaapi
    if "delete_anterior" in sys.modules:
        del sys.modules["delete_anterior"]
    idaapi.load_plugin("delete_anterior")