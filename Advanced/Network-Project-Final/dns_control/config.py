from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {'upstream_ip':'127.0.0.1','upstream_port':'5354','timeout':'2','ad_list_file':'ad_list.txt','sanction_list_file':'sanction_list.txt','sinkhole_ip':'0.0.0.0','proxy_ip':'192.0.2.10','local_ttl':'60','cache_enabled':'true','cache_max_entries':'100','real_dns_enabled':'false','filter_enabled':'true'}
EDITABLE = {'upstream_ip','upstream_port','timeout','sinkhole_ip','proxy_ip','local_ttl','cache_enabled','cache_max_entries','real_dns_enabled','filter_enabled'}

def load():
    data = DEFAULTS.copy()
    path = ROOT / 'config.txt'
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key, value = line.split('=', 1)
                if key.strip() in DEFAULTS: data[key.strip()] = value.strip()
    return data

def save(data):
    cfg = load()
    cfg.update(data)
    path = ROOT / 'config.txt'
    temp = path.with_suffix('.tmp')
    temp.write_text(''.join(f'{k}={v}\n' for k,v in cfg.items()), encoding='utf-8')
    temp.replace(path)

def list_path(name):
    cfg = load()
    filename = cfg['ad_list_file' if name == 'ads' else 'sanction_list_file']
    path = (ROOT / filename).resolve()
    if not path.is_relative_to(ROOT.resolve()): raise ValueError('Unsafe list path')
    return path
