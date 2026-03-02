from typing import Callable
from pathlib import Path
from unittest.mock import patch
from collections import Counter
import time
import subprocess

import requests
from urllib3.util import Retry

import yaml
import json
from profilarr.importer.strategies.format import FormatStrategy
from profilarr.importer.strategies.profile import ProfileStrategy
import logging

from declarr.utils import (
    add_defaults,
    deep_merge,
    del_keys,
    map_values,
    pp,
    prettify,
    read_file,
    to_dict,
    trace,
    unique,
)

log = logging.getLogger(__name__)


class FormatCompiler:
    def __init__(self, cfg):
        self.cfg = cfg

        state_dir = self.cfg["declarr"]["stateDir"]
        self.data_dir = Path(state_dir) / "format_data"

        self.update_data()

    def update_data(self):
        git_repo = self.cfg["declarr"].get("formatDbRepo", "")
        git_branch = self.cfg["declarr"].get("formatDbBranch", "stable")

        if not git_repo:
            log.error("no format data source found")
            return

        if not self.data_dir.exists() or not any(self.data_dir.iterdir()):
            subprocess.run(
                ["git", "clone", git_repo, "-b", git_branch, self.data_dir],
                check=True,
            )
            return

        latest_mod_time = max(
            f.stat().st_mtime for f in self.data_dir.rglob("*") if f.is_file()
        )

        if time.time() - latest_mod_time > 10 * 60:
            try:
                subprocess.run(
                    ["git", "pull", git_repo, git_branch, "--force"],
                    check=True,
                )
            except subprocess.CalledProcessError:
                subprocess.run(
                    ["rm", "-rf", self.data_dir],
                    check=True,
                )
                subprocess.run(
                    ["git", "clone", git_repo, "-b", git_branch, self.data_dir],
                    check=True,
                )

    def compile_formats(self, cfg):
        # use profilarr db as defaults
        original_profiles = cfg.get("qualityProfile") or {}
        def load_yaml(file_path: str):
            file_type = None
            name = ""
            if file_path.startswith("profile/"):
                file_type = "profile"
                name = file_path.removeprefix("profile/")
            elif file_path.startswith("custom_format/"):
                file_type = "format"
                name = file_path.removeprefix("custom_format/")
            else:
                log.error("unexpected path")
                raise Exception("unexpected path")

            format_cfg = (
                cfg.get(
                    {
                        "format": "customFormat",
                        "profile": "qualityProfile",
                    }[file_type]
                ).get(name, {})
                or {}
            )

            # pp(format_cfg)
            # pp(self.format_data_source.get_data(name, t))

            defaults = "{}"
            try:
                defaults = read_file(
                    self.data_dir
                    / {
                        "profile": "profiles",
                        "format": "custom_formats",
                    }[file_type]
                    / Path(name)
                )
            except FileNotFoundError:
                pass
            defaults = yaml.safe_load(defaults)

            format_data = deep_merge(format_cfg, defaults)

            return {"name": name, **format_data}

        def load_regex_patterns():
            patterns = {}

            for file in (self.data_dir / "regex_patterns").iterdir():
                if not file.is_file():
                    continue

                try:
                    data = yaml.safe_load(read_file(file))
                    patterns[data["name"]] = data["pattern"]
                except Exception:
                    # Silent fail for individual pattern files
                    pass

            # pp(patterns)
            return patterns

        with (
            patch(
                "profilarr.importer.compiler.get_language_import_score",
                new=lambda *_, **__: -99999,
            ),
            patch(
                "profilarr.importer.compiler.is_format_in_renames",
                new=lambda *_, **__: False,
            ),
            patch("profilarr.importer.strategies.profile.load_yaml", new=load_yaml),
            patch("profilarr.importer.strategies.format.load_yaml", new=load_yaml),
            patch("profilarr.importer.utils.load_yaml", new=load_yaml),
            patch(
                "profilarr.importer.compiler.load_regex_patterns",
                new=load_regex_patterns,
            ),
        ):
            server_cfg = {
                "type": cfg["declarr"]["type"],
                "arr_server": "http://localhost:8989",
                "api_key": "bafd0de9bc384a17881f27881a5c5e72",
                "import_as_unique": False,
            }

            compiled = ProfileStrategy(server_cfg).compile(
                cfg["qualityProfile"].keys(),
            )

            def extract_profile_format_names(profile_names):
                names = []
                for profile_name in profile_names:
                    profile_path = self.data_dir / "profiles" / f"{profile_name}.yml"
                    try:
                        data = yaml.safe_load(read_file(profile_path)) or {}
                    except Exception:
                        continue

                    def collect(list_name):
                        for item in data.get(list_name, []) or []:
                            if isinstance(item, str):
                                names.append(item)
                            elif isinstance(item, dict):
                                name = item.get("name")
                                if name:
                                    names.append(name)

                    collect("custom_formats")
                    if cfg["declarr"]["type"] == "radarr":
                        collect("custom_formats_radarr")
                    elif cfg["declarr"]["type"] == "sonarr":
                        collect("custom_formats_sonarr")

                return unique(names)

            format_names = extract_profile_format_names(cfg["qualityProfile"].keys())
            if cfg["customFormat"] is not None:
                format_names = unique(format_names + list(cfg["customFormat"].keys()))

            # Compile formats referenced by profiles (and any explicitly provided).
            compiled_formats = FormatStrategy(server_cfg).compile(
                format_names,
            )["formats"]

            # Optionally prefer raw YAML definitions from the format DB.
            # This keeps specs exactly as in the repo (e.g., release_title conditions).
            if format_names and cfg["declarr"].get("customFormatPreferRaw"):
                raw_map = {}
                for name in format_names:
                    try:
                        data = yaml.safe_load(
                            read_file(self.data_dir / "custom_formats" / f"{name}.yml")
                        )
                        if data:
                            raw_map[name] = {"name": name, **data}
                    except Exception:
                        pass
                if raw_map:
                    compiled_map = {f.get("name"): f for f in compiled_formats or []}
                    merged = {}
                    merged.update(compiled_map)
                    merged.update(raw_map)
                    compiled_formats = [v for _, v in merged.items()]

            # Fallback: read format YAMLs directly if compile returned nothing.
            if not compiled_formats and format_names:
                for name in format_names:
                    try:
                        data = yaml.safe_load(
                            read_file(self.data_dir / "custom_formats" / f"{name}.yml")
                        )
                        if data:
                            compiled_formats.append({"name": name, **data})
                    except Exception:
                        pass

            compiled["formats"] += compiled_formats
            # FormatStrategy(server_cfg).import_data(compiled)

        # Ensure formats referenced by profiles exist before applying profiles.
        # If customFormat is unset (None), auto-populate it from compiled profiles.
        if compiled["formats"]:
            cfg["customFormat"] = to_dict(compiled["formats"], "name")
        if cfg["qualityProfile"] is not None:
            cfg["qualityProfile"] = to_dict(
                compiled["profiles"],
                "name",
            )
            # Preserve per-profile overrides from the input config (e.g. formatScoreOverrides).
            for name, overrides in (original_profiles or {}).items():
                if name in cfg["qualityProfile"] and isinstance(overrides, dict):
                    if "formatScoreOverrides" in overrides:
                        cfg["qualityProfile"][name]["formatScoreOverrides"] = overrides[
                            "formatScoreOverrides"
                        ]

        return cfg


class ArrSyncEngine:
    def __init__(self, cfg, format_data_source):
        self.format_compiler = format_data_source

        meta_cfg = cfg["declarr"]
        self.cfg = cfg

        self.type = meta_cfg["type"]
        api_path = {
            "sonarr": "/api/v3",
            "radarr": "/api/v3",
            "lidarr": "/api/v1",
            "prowlarr": "/api/v1",
        }[self.type]
        self.base_url = meta_cfg["url"].strip("/")
        self.url = self.base_url + api_path

        adapter = requests.adapters.HTTPAdapter(
            max_retries=Retry(total=10, backoff_factor=0.1)
        )

        self.r = requests.Session()
        self.r.mount("http://", adapter)
        self.r.mount("https://", adapter)

        api_key = self.cfg["config"]["host"]["apiKey"]
        self.r.headers.update({"X-Api-Key": api_key})

        self.tag_map = {}
        self.profile_map = {}

        self.deferred_deletes = []
        self._cf_schema_map = None
        self._cf_schema_by_impl = None
        self._custom_format_errors = []

    def _base_req(self, name, f, path: str, body):
        body = {} if body is None else body

        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"{name} {self.url}{path} {prettify(body)}")
        else:
            log.info(f"{name} {self.url}{path}")

        res = f(self.url + path, json=body)
        log.debug(f"=> {prettify(res.text)}")

        if res.status_code < 300:
            return res.json()

        # res.raise_for_status()

        raise Exception(
            f"{name} {self.url}{path} "
            f"{json.dumps(body, indent=2)} "
            f"{json.dumps(res.json(), indent=2) if res.text else '""'}"
            f": {res.status_code}"
        )

    def get(self, path: str, body=None):
        return self._base_req("get ", self.r.get, path, body)

    def post(self, path: str, body=None):
        return self._base_req("post", self.r.post, path, body)

    def delete(self, path: str, body=None):
        return self._base_req("del ", self.r.delete, path, body)

    def deferr_delete(self, path: str, body=None):
        self.deferred_deletes.append([path, body])

    def put(self, path: str, body=None):
        return self._base_req("put ", self.r.put, path, body)

    def sync_tags(self):
        tags = self.cfg.get("tag", [])

        for k in ["indexer", "indexerProxy", "downloadClient", "applications"]:
            if k not in self.cfg:
                continue
            if self.cfg[k] is None:
                continue
            for y in self.cfg[k].values():
                tags += y.get("tags", [])

        if self.cfg.get("customFormat") is not None:
            for fmt in self.cfg["customFormat"].values():
                tags += fmt.get("tags", [])

        if self.type == "lidarr":
            tags += sum(
                [x.get("defaultTags") for x in self.cfg["rootFolder"].values()],
                [],
            )

        existing = [v["label"] for v in self.get("/tag")]
        for tag in [t for t in (self._normalise_tag(tag) for tag in unique(tags)) if t]:
            if tag not in existing:
                self.post("/tag", {"label": tag})

            # TODO: delete unused tags

        self.tag_map = {self._normalise_tag(v["label"]): v["id"] for v in self.get("/tag")}

    @staticmethod
    def _normalise_tag(tag: str) -> str:
        tag = tag.lower()
        tag = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in tag)
        tag = tag.strip("-")
        while "--" in tag:
            tag = tag.replace("--", "-")
        return tag

    def _normalise_custom_format(self, fmt: dict) -> dict:
        self._load_custom_format_schema()
        raw_fmt = None
        if self.cfg.get("declarr", {}).get("customFormatPreferRaw") and fmt.get("name"):
            try:
                raw_path = (
                    self.format_compiler.data_dir
                    / "custom_formats"
                    / f"{fmt.get('name')}.yml"
                )
                if raw_path.exists():
                    raw_fmt = yaml.safe_load(read_file(raw_path)) or {}
            except Exception:
                raw_fmt = None

        specifications = fmt.get("specifications")
        if raw_fmt:
            specifications = raw_fmt.get("specifications") or raw_fmt.get("conditions")
        if not specifications:
            specifications = fmt.get("conditions")
        specifications = specifications or []
        normalised_specs = []
        for spec in specifications:
            if not isinstance(spec, dict):
                continue
            implementation = spec.get("implementation")
            if not implementation:
                key = spec.get("type") or spec.get("name") or ""
                implementation = self._cf_schema_map.get(
                    self._normalise_impl_key(key), ""
                )
                if implementation:
                    spec = {**spec, "implementation": implementation}
            if implementation and self._cf_schema_by_impl:
                schema = self._cf_schema_by_impl.get(implementation, {})
                schema_fields = schema.get("fields", []) or []
                field_names = {f.get("name") for f in schema_fields}
                # Fill field values expected by Radarr schema.
                values = {}
                for field in field_names:
                    if field in spec:
                        values[field] = spec[field]
                if "value" in field_names and "value" not in values:
                    if "pattern" in spec:
                        values["value"] = spec["pattern"]
                    elif "source" in spec:
                        values["value"] = spec["source"]
                    elif "resolution" in spec:
                        values["value"] = spec["resolution"]
                if "value" in values:
                    original_value = values["value"]
                    # If schema defines select options, map string values to select IDs.
                    if implementation and self._cf_schema_by_impl:
                        schema = self._cf_schema_by_impl.get(implementation, {})
                        schema_fields = schema.get("fields", []) or []
                        select_field = next(
                            (f for f in schema_fields if f.get("name") == "value"),
                            None,
                        )
                        select_opts = (
                            select_field.get("selectOptions")
                            if select_field
                            else None
                        )
                        if isinstance(values["value"], str) and isinstance(
                            select_opts, list
                        ):
                            opt_map = {}
                            for opt in select_opts:
                                if isinstance(opt, dict):
                                    name = opt.get("name")
                                    val = opt.get("value")
                                    if name is not None and val is not None:
                                        key = "".join(
                                            ch for ch in str(name).lower() if ch.isalnum()
                                        )
                                        opt_map[key] = val
                            key = "".join(
                                ch for ch in values["value"].lower() if ch.isalnum()
                            )
                            if key in opt_map:
                                values["value"] = opt_map[key]
                            elif implementation == "SourceSpecification":
                                # Heuristic aliases for Sonarr/Radarr source names.
                                alias_map = {
                                    "webdl": "web",
                                    "web": "web",
                                    "webrip": "webrip",
                                    "bluray": "bluray",
                                    "blurayremux": "blurayraw",
                                    "blurayraw": "blurayraw",
                                    "dvd": "dvd",
                                    "hdtv": "television",
                                    "tv": "television",
                                    "rawhd": "televisionraw",
                                    "televisionraw": "televisionraw",
                                }
                                alt = alias_map.get(key)
                                if alt and alt in opt_map:
                                    values["value"] = opt_map[alt]
                    if implementation == "ResolutionSpecification":
                        if isinstance(values["value"], str):
                            digits = "".join(ch for ch in values["value"] if ch.isdigit())
                            values["value"] = int(digits) if digits else 0
                    elif implementation == "SourceSpecification":
                        if isinstance(values["value"], str):
                            values["value"] = (
                                values["value"]
                                .lower()
                                .replace("_", "")
                                .replace("-", "")
                                .replace(" ", "")
                            )
                    elif isinstance(values["value"], str):
                        values["value"] = values["value"].strip()
                    # Some Radarr versions still read top-level Value.
                    spec["value"] = values["value"]
                spec = {
                    **spec,
                    "fields": [{"name": k, "value": v} for k, v in values.items()],
                }
                # Avoid confusing schema binding with extra legacy keys.
                spec.pop("source", None)
                spec.pop("resolution", None)
                spec.pop("pattern", None)
            normalised_specs.append(spec)
        return {
            **{k: val for k, val in fmt.items() if k != "conditions"},
            "specifications": normalised_specs,
            "tests": fmt.get("tests") or [],
            "tags": [
                self.tag_map[self._normalise_tag(t)] if isinstance(t, str) else t
                for t in (fmt.get("tags") or [])
            ],
        }

    def _load_custom_format_schema(self) -> None:
        if self._cf_schema_map is not None:
            return
        self._cf_schema_map = {}
        self._cf_schema_by_impl = {}
        self._cf_schema_dump = []
        try:
            data = self.get("/customformat/schema")
        except Exception:
            return
        for spec in data or []:
            implementation = (
                spec.get("implementation")
                or spec.get("implementationName")
                or spec.get("type")
            )
            if implementation:
                self._cf_schema_by_impl[implementation] = spec
                fields = spec.get("fields") or []
                self._cf_schema_dump.append(
                    {
                        "name": spec.get("name"),
                        "implementation": implementation,
                        "fields": [
                            {
                                "name": f.get("name"),
                                "type": f.get("type"),
                                "valueType": f.get("valueType"),
                                "selectOptions": f.get("selectOptions")
                                or f.get("select")
                                or f.get("items"),
                            }
                            for f in fields
                        ],
                    }
                )
            for key in [
                spec.get("name"),
                spec.get("implementation"),
                spec.get("implementationName"),
                spec.get("type"),
            ]:
                if key and implementation:
                    self._cf_schema_map[self._normalise_impl_key(key)] = implementation

    @staticmethod
    def _normalise_impl_key(value: str) -> str:
        return "".join(ch for ch in value.lower() if ch.isalnum())

    def sync_resources(
        self,
        path: str,
        cfg: None | dict,
        defaults: Callable[[str, dict], dict] = lambda k, v: v,
        allow_error=False,
        key: str = "name",
        delete_missing: bool = True,
    ):
        if cfg is None:
            return

        existing = to_dict(self.get(path), key)
        if delete_missing:
            for name, dat in existing.items():
                if name not in cfg:
                    self.deferr_delete(f"{path}/{dat['id']}")

        cfg = map_values(cfg, defaults)
        cfg = map_values(
            cfg,
            lambda k, v: {
                "name": k,
                **v,
            },
        )

        for name, dat in cfg.items():
            try:
                if name in existing:
                    if (
                        path == "/customformat"
                        and self.cfg.get("declarr", {}).get("customFormatRecreate")
                        and not self._custom_format_equal(existing[name], dat)
                    ):
                        self.delete(f"{path}/{existing[name]['id']}")
                        self.post(path, dat)
                    else:
                        self.put(
                            f"{path}/{existing[name]['id']}",
                            {**existing[name], **dat},
                        )
                else:
                    self.post(path, dat)

            except Exception as e:
                if path == "/customformat":
                    self._custom_format_errors.append(
                        {
                            "name": name,
                            "error": str(e),
                            "summary": self._summarise_custom_format(dat),
                        }
                    )
                if not allow_error:
                    raise e
                log.error(e)

    # format_fields
    # def serialise_fields(self, f):
    #     return

    def sync_contracts(
        self,
        path: str,
        cfg: dict,
        defaults: Callable[[str, dict], dict] = lambda k, v: v,
        scheme_key=["implementation", "implementation"],
        # only_update=False,
    ):
        if cfg is None:
            return

        existing = to_dict(self.get(path), "name")
        # pp(existing)
        existing = map_values(
            existing,
            lambda _, val: {
                **val,
                "fields": {v["name"]: v.get("value", None) for v in val["fields"]},
            },
        )
        cfg = map_values(
            cfg,
            lambda k, v: deep_merge(v, existing.get(k, {})),
        )

        cfg = map_values(
            cfg,
            lambda k, v: {
                "enable": True,
                "name": k,
                **v,
            },
        )

        # TODO: validate config against schema
        # TODO: sane select options (convert string to the enum index)
        schema = map_values(
            to_dict(self.get(f"{path}/schema"), scheme_key[0]),
            # i don't know why but the arr clients always seem to delete the
            # "presets" key from the schema. (monkey see, monkey do)
            # https://github.com/Lidarr/Lidarr/blob/7277458721256b36ab6c248f5f3b34da94e4faf9/frontend/src/Utilities/State/getProviderState.js#L44
            lambda _, v: del_keys(
                {
                    **v,
                    "fields": {v["name"]: v.get("value", None) for v in v["fields"]},
                },
                ["presets"],
            ),
        )
        cfg = map_values(
            cfg,
            lambda k, v: deep_merge(v, schema[v[scheme_key[1]]]),
        )

        cfg = map_values(
            cfg,
            lambda k, v: {
                "enable": True,
                "name": k,
                **v,
            },
        )
        cfg = map_values(cfg, defaults)
        cfg = map_values(
            cfg,
            lambda name, obj: {
                **obj,
                "tags": [
                    self.tag_map[t.lower()] if isinstance(t, str) else t
                    for t in obj.get("tags", [])
                ],
                "fields": [
                    {"name": k} if v is None else {"name": k, "value": v}
                    for k, v in obj.get("fields", {}).items()
                ],
            },
        )

        for name, data in existing.items():
            if name not in cfg.keys():  # and not only_update:
                self.deferr_delete(f"{path}/{data['id']}")

        for name, data in cfg.items():
            if name in existing.keys():
                self.put(f"{path}/{existing[name]['id']}", data)
            # elif not only_update:
            else:
                self.post(path, data)
            # else:
            #     raise Exception(f"Cant create more instances of the {path} resource")

    # def sync_paths(self, paths: list[str]):
    #     pass

    def recursive_sync(self, obj, resource=""):
        if isinstance(obj, list):
            for body in obj:
                self.post(resource, body)

            return

        has_primative_val = any(
            not isinstance(
                obj[key],
                (dict, list),
            )
            for key in obj
        )
        if has_primative_val or "__req" in obj:
            obj.pop("__req", None)
            self.put(
                resource,
                deep_merge(obj, self.get(resource)),
            )
            return

        # if resource in paths:
        #     self.put(
        #         resource,
        #         deep_merge(obj, self.get(resource)),
        #     )

        for key in obj:
            self.recursive_sync(obj[key], f"{resource}/{key}")

    def sync(self):
        log.debug(
            f"{self.cfg['declarr']['name']} cfg: {json.dumps(self.cfg, indent=2)}"
        )
        self.r.get(self.base_url + "/ping").raise_for_status()

        # TODO: add a strict mode where everything not declared is reset
        #  could be done via setting this to {} instead of None
        self.cfg = {
            "downloadClient": None,
            "appProfile": None,
            "applications": None,
            #
            "indexer": None,
            "indexerProxie": None,
            #
            "qualityDefinition": {},
            #
            "customFormat": None,
            "qualityProfile": None,
            #
            "rootFolder": None,
            #
            "importList": None,
            "notification": None,
            **self.cfg,
        }

        if self.type in ("sonarr", "radarr"):
            self.cfg = self.format_compiler.compile_formats(self.cfg)

        self.sync_tags()

        # pp(self.tag_map)

        self.sync_contracts("/downloadClient", self.cfg["downloadClient"])

        # print(self.profile_map)
        if self.type in ("prowlarr",):
            self.sync_resources(
                "/appprofile",
                self.cfg["appProfile"],
                lambda k, v: {
                    "enableRss": True,
                    "enableAutomaticSearch": True,
                    "enableInteractiveSearch": True,
                    "minimumSeeders": 1,
                    **v,
                },
            )
            profile_map = {
                v["name"]: v["id"]  #
                for v in self.get("/appprofile")  #
                if self.cfg["appProfile"] is None  #
                or v["name"] in self.cfg["appProfile"]
            }

            def gen_profile_id(v):
                avalible_ids = profile_map.values()

                # the default id is the first created appProfile that exists
                default_id = min(avalible_ids)

                if "appProfileId" not in v:
                    return default_id

                id = v["appProfileId"]
                if isinstance(id, int):
                    # reassign new id if indexers appProfile got deleted
                    # this should not happen
                    return id if id in avalible_ids else default_id

                return profile_map[id]

            # TODO: make it possible to set /indexer for sonarr, radarr, lidarr
            self.sync_contracts(
                "/indexer",
                self.cfg["indexer"],
                lambda k, v: {
                    **v,
                    "appProfileId": gen_profile_id(v),
                },
                scheme_key=["name", "indexerName"],
            )

            self.sync_contracts("/applications", self.cfg["applications"])

            self.sync_contracts("/indexerProxy", self.cfg["indexerProxy"])

        if self.type in ("sonarr", "radarr", "lidarr"):
            qmap = to_dict(
                self.get("/qualityDefinition"),
                "title",
            )

            for name, x in self.cfg["qualityDefinition"].items():
                self.put(
                    f"/qualityDefinition/{qmap[name]['id']}",
                    deep_merge(x, qmap[name]),
                )

            # self.sync_contracts(
            #     "/metadata",
            #     self.cfg["metadata"],
            #     only_update=True,
            # )

        if self.type in ("sonarr", "radarr"):
            self.sync_resources(
                "/customformat",
                self.cfg["customFormat"],
                lambda _, v: self._normalise_custom_format(v),
                allow_error=True,
                delete_missing=False,
            )

            formats = self.get("/customformat")
            format_id_map = {d["name"]: d["id"] for d in formats}

            def ensure_formats_exist(names):
                nonlocal format_id_map
                if self.cfg["customFormat"] is None:
                    return

                missing = [n for n in names if n not in format_id_map]
                if not missing:
                    return

                for name in missing:
                    if name not in self.cfg["customFormat"]:
                        continue
                    try:
                        self.post(
                            "/customformat",
                            {
                                "name": name,
                                **self._normalise_custom_format(
                                    self.cfg["customFormat"][name]
                                ),
                            },
                        )
                    except Exception as e:
                        log.error(e)

                format_id_map = {
                    d["name"]: d["id"] for d in self.get("/customformat")
                }

            def build_score_map(profile_name: str, v: dict) -> dict:
                score_map = {
                    item.get("name"): item.get("score", 0)
                    for item in v.get("formatItems", [])
                    if item.get("name") is not None
                }
                if score_map:
                    overrides = v.get("formatScoreOverrides", {}) or {}
                    for name, score in overrides.items():
                        score_map[name] = score
                    return score_map

                # Fallback: load profile YAML to extract custom format scores.
                try:
                    profile_path = (
                        self.format_compiler.data_dir
                        / "profiles"
                        / f"{profile_name}.yml"
                    )
                    data = yaml.safe_load(read_file(profile_path)) or {}
                    formats = list(data.get("custom_formats", []))
                    if self.type == "radarr":
                        formats += data.get("custom_formats_radarr", [])
                    elif self.type == "sonarr":
                        formats += data.get("custom_formats_sonarr", [])

                    score_map = {}
                    for f in formats:
                        if isinstance(f, str):
                            score_map[f] = 0
                            continue
                        name = f.get("name")
                        if name is not None:
                            score_map[name] = f.get("score", 0)
                    overrides = v.get("formatScoreOverrides", {}) or {}
                    for name, score in overrides.items():
                        score_map[name] = score
                    return score_map
                except Exception:
                    return {}

            if self.cfg["qualityProfile"] is not None:
                all_format_names = []
                for name, v in self.cfg["qualityProfile"].items():
                    for item in v.get("formatItems", []):
                        fmt_name = item.get("name")
                        if fmt_name:
                            all_format_names.append(fmt_name)
                    if not v.get("formatItems"):
                        all_format_names += list(build_score_map(name, v).keys())
                ensure_formats_exist(unique(all_format_names))

            def gen_formats_items(profile_name: str, v: dict):
                # Radarr requires all custom formats to be present in profiles.
                score_map = build_score_map(profile_name, v)
                return [
                    {
                        "name": name,
                        "format": fmt_id,
                        "score": score_map.get(name, 0),
                    }
                    for name, fmt_id in format_id_map.items()
                ]

            self.sync_resources(
                "/qualityprofile",
                self.cfg["qualityProfile"],
                lambda k, v: {
                    **v,
                    "formatItems": gen_formats_items(k, v),
                },
                allow_error=True,
            )

        if self.type in ("sonarr", "radarr") and self.cfg["rootFolder"] is not None:
            cfg = {v: {"path": v} for v in self.cfg.get("rootFolder", [])}

            path = "/rootFolder"

            existing = to_dict(self.get(path), "path")
            for name, data in existing.items():
                if name not in cfg.keys():
                    self.delete(f"{path}/{data['id']}")

            for name, data in cfg.items():
                if name not in existing.keys():
                    self.post(path, data)

        if self.type == "lidarr":
            # cfg = {
            #     v["path"]: {"name": k, **v}
            #     for k, v in self.cfg.get("rootFolder", {}).items()
            # }

            quality_profile_map = {
                v["name"]: v["id"]  #
                for v in self.get("/qualityprofile")
            }
            metadata_profile_map = {
                v["name"]: v["id"]  #
                for v in self.get("/metadataprofile")
            }

            self.sync_resources(
                "/rootFolder",
                self.cfg["rootFolder"],
                lambda k, v: {
                    **v,
                    # "name": k,
                    "defaultTags": [
                        self.tag_map[t.lower()] if isinstance(t, str) else t
                        for t in v.get("tags", [])
                    ],
                    "defaultQualityProfileId": quality_profile_map[
                        v["defaultQualityProfileId"]
                    ],
                    "defaultMetadataProfileId": metadata_profile_map[
                        v["defaultMetadataProfileId"]
                    ],
                },
                # key="path",
            )

            # manual: config/metadataProvider

            # TODO:: custom formats and quality profiles for lidarr

        # FIXME: defaults are broken
        self.sync_contracts("/notification", self.cfg["notification"])

        # self.sync_contracts("/importlist", self.cfg["importList"])

        # /importlist can be both post to to update setting
        # and put to to create a new resource, bruh

        # TODO: /autoTagging

        # TODO: explicitly set paths
        #  eg /config/ui, /config/host
        self.recursive_sync(self.cfg["config"], resource="/config")

        for path, body in self.deferred_deletes:
            try:
                self.delete(path, body)
            except Exception:
                pass

        if self._custom_format_errors:
            log.error("Custom format errors summary (last run):")
            for err in self._custom_format_errors:
                log.error(
                    f"- {err['name']}: {err['error']} | {err['summary']}"
                )
            if getattr(self, "_cf_schema_dump", None):
                log.error("Custom format schema summary (last run):")
                for item in self._cf_schema_dump:
                    field_parts = []
                    for f in (item.get("fields") or []):
                        ftype = f.get("type") or f.get("valueType")
                        opts = f.get("selectOptions")
                        if isinstance(opts, list) and opts:
                            opt_preview = ",".join(
                                str(o.get("value") or o.get("id") or o.get("key") or o)
                                for o in opts[:12]
                            )
                            field_parts.append(f"{f.get('name')}:{ftype}[{opt_preview}]")
                        else:
                            field_parts.append(f"{f.get('name')}:{ftype}")
                    log.error(
                        f"- {item.get('name')} "
                        f"({item.get('implementation')}): {', '.join(field_parts)}"
                    )

    @staticmethod
    def _summarise_custom_format(fmt: dict) -> str:
        specs = fmt.get("specifications") or []
        parts = []
        for spec in specs:
            impl = spec.get("implementation") or ""
            stype = spec.get("type") or ""
            fields = spec.get("fields") or []
            field_dump = ",".join(
                f"{f.get('name')}={f.get('value')}" for f in fields
            )
            parts.append(
                f"{stype or 'unknown'}:{impl or 'unknown'} "
                f"fields={len(fields)}[{field_dump}]"
            )
        return "specs=[" + ", ".join(parts) + "]"

    def _custom_format_equal(self, existing: dict, desired: dict) -> bool:
        def spec_signature(specs):
            out = []
            for spec in specs or []:
                impl = (
                    spec.get("implementation")
                    or spec.get("implementationName")
                    or spec.get("type")
                )
                negate = bool(spec.get("negate", False))
                required = bool(spec.get("required", False))
                fields = spec.get("fields") or []
                field_map = {f.get("name"): f.get("value") for f in fields}
                if impl in ("SizeSpecification", "YearSpecification"):
                    value = tuple(sorted(field_map.items()))
                else:
                    value = field_map.get("value", spec.get("value"))
                out.append((impl, negate, required, value))
            return Counter(out)

        return spec_signature(existing.get("specifications")) == spec_signature(
            desired.get("specifications")
        )
