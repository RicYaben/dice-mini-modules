from dice.module import Module, new_module, new_registry
from dice.query import query_db
from dice.config import TAGGER

from tdigest import TDigest

from modules.noise.factory import NoiseEvaluator, NoiseEvaluatorFactory

def is_timeout(fp) -> bool:
    return fp["probe_status"] == "io-timeout" and fp["data"]

def iec_tarpit(mod: Module) -> NoiseEvaluator:
    'Calculate the distribution of IOAs and return when crosses the 95prc'

    q = """
    SELECT
        host,
        COUNT(DISTINCT ioa) AS cioas36
    FROM (
        SELECT
            f.host,
            json_extract(ioa.value, '$') AS ioa
        FROM fingerprints f
        -- explode asdus[]
        CROSS JOIN json_each(json_extract(f.data, '$.asdus')) AS asdus
        -- explode asdus[].IOAs[]
        CROSS JOIN json_each(json_extract(asdus.value, '$.IOAs')) AS ioa
        WHERE f.protocol = 'iec104'
        AND json_extract(asdus.value, '$.TypeID') = 36
    )
    GROUP BY host
    """

    digest = TDigest()
    for r in mod.repo().query(q):
        digest.update(r["cioas36"])

    threshold = digest.percentile(95)
    def ev(fp) -> None:
        # If it timed out and the number of IOAs with type 36 (M_ME_TF_1), a measured value with timestamp
        # is very large, then flag this
        if len(fp["asdus"]) > threshold:
            tag = mod.make_fp_tag(fp, "tarpit", "too many IOAs")
            mod.save(tag)
    return ev

def modbus_tarpit(mod: Module) -> NoiseEvaluator:
    'Too many objects in the mei response'
    
    # TODO: at least one object and more follows
    q = """
    SELECT objects, COUNT(objects) AS count
    FROM fingerprints
    WHERE protocol == "modbus"
    AND more_follows == True;
    """

    digest = TDigest()
    for r in mod.repo().query(q):
        digest.update(r["count"])
    threshold = digest.percentile(95)
    # 5 is the minimum required objects in the
    # mei response
    MIN_REQUIRED = 5
    if threshold < MIN_REQUIRED: threshold = MIN_REQUIRED
    def ev(fp) -> None:
        if len(fp["objects"]) > threshold:
            tag = mod.make_tag(fp, "tarpit", "too many objects. More follows")
            mod.save(tag)
    return ev
        
def make_tarpit_factory(mod: Module) -> NoiseEvaluatorFactory:
    factory = NoiseEvaluatorFactory(mod)
    return factory.add("iec104", iec_tarpit).add("modbus", modbus_tarpit)

def tarpit_tag(mod: Module) -> None:
    factory = make_tarpit_factory(mod)
    # TODO: need to add status into the fps
    for p in factory.supported():
        ev = factory.get(p)
        if not ev:
            raise Exception(f"evaluator supported but not found: {p}")
        
        for fp in mod.query(query_db("fingerprints", protocol=p)):
            ev(fp)

def hostility_init(mod: Module) -> None:
    mod.register_tag("tarpit", "Determines whether a service is a tarpot by picking lengthy connections with abnormally large amounts of data")

def make_tarpit_module() -> Module:
    return new_module(TAGGER, "tarpit", tarpit_tag, hostility_init)

hostility_reg = new_registry("hostility").add(make_tarpit_module())