from dice.query import query_db
from dice.module import Module, new_module
from dice.config import TAGGER

def aletheia_tag(mod: Module) -> None:
    '''hosting fingerprinting TCP window-based and scaling factor'''
    # ZMap records: window size and scaling factor
    q_not = query_db("records_zmap",
        window__lte=0,
    )

    q_python = query_db(
        "records_zmap",
        window__bt=[6370,6379],
        tcpopt_wscale=64,
    )

    q_cloud = query_db(
        "records_zmap",
        window__bt=[502,509],
        tcpopt_wscale__bt=[128,256], 
    )

    q_cloud_2 = query_db(
        "records_zmap",
        window__bt=[64_240,65_152],
        tcpopt_wscale__bt=[128,256], 
    )

    for q, d in [(q_not, "0 window"), (q_python, "python"), (q_cloud, "cloud"), (q_cloud_2, "cloud")]:
        hosts = mod.query(q)
        tags = []
        for h in hosts:
            t = mod.make_tag(h["saddr"], "aletheia", details=d, port=h["dport"])
            tags.append(t)
        mod.save(*tags)


def aletheia_init(mod: Module) -> None:
    mod.register_tag("aletheia", "OT fingerprinting method from A. Cordeiro et al.")

def make_aletheia_module() -> Module:
    return new_module(TAGGER, "aletheia", aletheia_tag, aletheia_init)