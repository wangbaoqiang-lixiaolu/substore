#!/usr/bin/env python3
"""Mocked checks for chain-mihomo.js. No real subscriptions or proxy servers."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent
JS = ROOT / "chain-mihomo.js"
TEMPLATE = ROOT / "chain-mihomo.yaml"
MIHOMO = pathlib.Path(os.environ.get("MIHOMO", "/tmp/mihomo"))

RULE_SAMPLE = {
    "domain": ("private", "ads", "apple", "icloud", "google", "gfw", "proxy-list", "tld-not-cn", "cn-domain"),
    "classical": (
        "ai",
        "social",
        "messaging",
        "media",
        "games-cn",
        "games",
        "github",
        "microsoft",
        "bank-cn",
        "finance",
        "crypto",
        "downloads",
    ),
    "ipcidr": ("lan-ip", "cn-ip", "telegram-ip"),
}


def run_js(source, expression):
    program = (
        "const fs=require('fs'); const vm=require('vm'); const ctx={console};"
        "vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'), ctx);"
        "Promise.resolve(eval(process.argv[2])).then(value => {"
        "  process.stdout.write(JSON.stringify(value));"
        "}).catch(error => { process.stderr.write(error && error.message ? error.message : String(error)); process.exit(2); });"
    )
    result = subprocess.run(
        ["node", "-e", program, str(JS), expression],
        input=source.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode() or result.stdout.decode())
    return json.loads(result.stdout.decode() or "null")


def build(template, proxies):
    payload = json.dumps({"template": template, "proxies": proxies}, ensure_ascii=False)
    expression = (
        "(function(){ const input=JSON.parse(require('fs').readFileSync(0,'utf8'));"
        " return ctx.buildChainConfig(input.template, input.proxies); })()"
    )
    return run_js(payload, expression)


def node(name, server, port, **extra):
    item = {
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": "aes-128-gcm",
        "password": "mock-password",
    }
    item.update(extra)
    return item


class ChainConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = yaml.safe_load(TEMPLATE.read_text())

    def collection(self):
        return [
            node("落地-甲", "192.0.2.10", 2001, type="vmess", udp=True),
            node("落地-甲", "192.0.2.11", 2002, type="vmess"),
            node("🇺🇸 落地-乙", "192.0.2.12", 2003, type="vmess"),
            node("🇺🇸落地-丙 [IPv6]", "192.0.2.13", 2004, type="vmess"),
            node("花云-入口", "192.0.2.1", 1001, type="ss"),
            node("🇭🇰 花云-落地-不是出口", "192.0.2.2", 1002, type="trojan"),
            node("自建-入口", "192.0.2.3", 1003, type="vmess"),
            node("🇯🇵守候网络-入口 [IPv6]", "192.0.2.4", 1004, type="ss"),
        ]

    def test_repeat_application_is_stable(self):
        proxies = self.collection()
        first = build(self.template, proxies)
        second = build(self.template, proxies)
        self.assertEqual(first, second)
        again = build(first, first["proxies"])
        self.assertEqual([item["name"] for item in first["proxies"]], [item["name"] for item in again["proxies"]])
        self.assertEqual(
            [item.get("dialer-proxy") for item in first["proxies"]],
            [item.get("dialer-proxy") for item in again["proxies"]],
        )
        exit_names = [item["name"] for item in first["proxies"] if item["name"].startswith("出口·")]
        self.assertEqual(exit_names[0], "出口·落地-甲")
        self.assertEqual(exit_names[1], "出口·落地-甲 #2")

    def test_membership_dialer_and_defaults(self):
        config = build(self.template, self.collection())
        reloaded = yaml.safe_load(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
        self.assertEqual(reloaded["dns"]["ipv6"], False)
        self.assertEqual(reloaded["dns"]["respect-rules"], False)
        names = [item["name"] for item in reloaded["proxies"]]
        self.assertEqual(
            names,
            [
                "入口·花云-入口",
                "入口·🇭🇰 花云-落地-不是出口",
                "入口·自建-入口",
                "入口·🇯🇵守候网络-入口 [IPv6]",
                "出口·落地-甲",
                "出口·落地-甲 #2",
                "出口·🇺🇸 落地-乙",
                "出口·🇺🇸落地-丙 [IPv6]",
            ],
        )
        groups = {item["name"]: item for item in reloaded["proxy-groups"]}
        self.assertEqual(groups["入口选择"]["proxies"], names[:4])
        self.assertEqual(groups["出口选择"]["proxies"], names[4:])
        self.assertEqual(groups["入口选择"]["empty-fallback"], "REJECT")
        self.assertEqual(groups["出口选择"]["empty-fallback"], "REJECT")
        self.assertNotIn("include-all", groups["入口选择"])
        self.assertNotIn("dialer-proxy", groups["出口选择"])
        by_name = {item["name"]: item for item in reloaded["proxies"]}
        self.assertNotIn("dialer-proxy", by_name["入口·花云-入口"])
        self.assertNotIn("dialer-proxy", by_name["入口·🇭🇰 花云-落地-不是出口"])
        self.assertEqual(by_name["出口·落地-甲"]["dialer-proxy"], "入口选择")
        self.assertEqual(by_name["出口·🇺🇸 落地-乙"]["type"], "vmess")
        self.assertTrue(by_name["出口·落地-甲"]["udp"])
        for name in ("默认代理", "AI 服务", "消息与社交", "流媒体与音乐", "游戏", "开发与 GitHub", "微软服务", "苹果服务", "谷歌服务"):
            self.assertEqual(groups[name]["type"], "select")
            self.assertEqual(groups[name]["proxies"][0], "出口选择")
            self.assertNotIn("DIRECT", groups[name]["proxies"][:1])
        self.assertEqual(groups["漏网之鱼"]["proxies"][0], "默认代理")
        self.assertEqual(groups["金融服务"]["proxies"][0], "DIRECT")
        self.assertEqual(groups["广告拦截"]["proxies"][0], "REJECT")
        self.assertEqual(groups["国内与局域网"]["proxies"][0], "DIRECT")
        self.assertTrue(all(item["type"] == "select" for item in reloaded["proxy-groups"]))
        self.assert_acyclic(reloaded)
        self.assert_rule_priority(reloaded["rules"])

    def test_missing_empty_duplicate_and_blocked_exit(self):
        with self.assertRaises(RuntimeError) as empty:
            build(self.template, [])
        self.assertIn("没有节点", str(empty.exception))

        with self.assertRaises(RuntimeError) as no_exit:
            build(self.template, [node("花云-只有入口", "192.0.2.1", 1001, type="ss")])
        self.assertIn("落地-", str(no_exit.exception))

        with self.assertRaises(RuntimeError) as no_entrance:
            build(self.template, [node("落地-只有出口", "192.0.2.10", 2001, type="vmess")])
        self.assertIn("入口", str(no_entrance.exception))

        with self.assertRaises(RuntimeError) as unknown:
            build(
                self.template,
                [
                    node("花云-入口", "192.0.2.1", 1001, type="ss"),
                    node("落地-出口", "192.0.2.10", 2001, type="vmess"),
                    node("美国节点", "192.0.2.3", 1003, type="ss"),
                    node("落地节点", "192.0.2.4", 1004, type="vmess"),
                    node("🇺🇸🇯🇵 落地-两个国旗", "192.0.2.11", 2002, type="vmess"),
                ],
            )
        message = str(unknown.exception)
        self.assertIn("美国节点", message)
        self.assertIn("落地节点", message)
        self.assertIn("两个国旗", message)
        self.assertNotIn("192.0.2.3", message)

        with self.assertRaises(RuntimeError) as shared:
            build(
                self.template,
                [
                    node("花云-甲", "192.0.2.8", 443, type="ss"),
                    node("落地-乙", "192.0.2.8", 443, type="vmess"),
                ],
            )
        self.assertNotIn("192.0.2.8", str(shared.exception))
        self.assertIn("同一个服务器和端口", str(shared.exception))

        with self.assertRaises(RuntimeError) as blocked:
            build(
                self.template,
                [
                    node("花云-入口", "192.0.2.1", 1001, type="hysteria2"),
                    node("落地-坏出口", "192.0.2.10", 2001, type="hysteria2", password="mock-password"),
                    node("落地-现实", "192.0.2.11", 2002, type="vless", **{"reality-opts": {"public-key": "mock"}}),
                ],
            )
        blocked_message = str(blocked.exception)
        self.assertIn("落地-坏出口", blocked_message)
        self.assertIn("Hysteria2", blocked_message)
        self.assertIn("REALITY", blocked_message)
        self.assertNotIn("mock-password", blocked_message)

    def test_main_uses_named_sources_and_keeps_the_whole_config(self):
        payload = json.dumps({"template": self.template}, ensure_ascii=False)
        expression = r"""
(async function(){
  const input = JSON.parse(require('fs').readFileSync(0,'utf8'));
  const calls = [];
  ctx.produceArtifact = async function(query){
    calls.push(query);
    if (query.name === '合并' && query.type === 'collection') {
      return [
        {name:'花云-甲', type:'ss', server:'192.0.2.1', port:1, cipher:'aes-128-gcm', password:'mock-password', _subName:'secret-source'},
        {name:'落地-乙', type:'vmess', server:'192.0.2.2', port:2, uuid:'mock-uuid'}
      ];
    }
    throw new Error('没有名为 ' + query.name + ' 的订阅');
  };
  const config = await ctx.main(input.template);
  return {calls, keys:Object.keys(config), proxies:config.proxies, rules:config.rules.length};
})()
"""
        result = run_js(payload, expression)
        self.assertEqual(result["calls"][0]["platform"], "mihomo")
        self.assertEqual(result["calls"][0]["produceType"], "internal")
        self.assertEqual(result["calls"][0]["type"], "collection")
        self.assertEqual(result["calls"][0]["name"], "合并")
        self.assertEqual(len(result["calls"]), 1)
        self.assertIn("dns", result["keys"])
        self.assertIn("rules", result["keys"])
        self.assertIn("proxy-groups", result["keys"])
        self.assertNotIn("_subName", result["proxies"][0])
        self.assertGreater(result["rules"], 10)

        with self.assertRaises(RuntimeError) as missing:
            run_js(
                payload,
                "(async function(){ const input=JSON.parse(require('fs').readFileSync(0,'utf8'));"
                " ctx.produceArtifact=async () => { throw new Error('找不到'); }; return ctx.main(input.template); })()",
            )
        self.assertIn("读不到组合订阅", str(missing.exception))
        self.assertIn("合并", str(missing.exception))

    def test_public_rule_urls_match_declared_behavior(self):
        providers = self.template["rule-providers"]
        self.assertEqual(set(RULE_SAMPLE), {"domain", "classical", "ipcidr"})
        seen = set()
        for behavior, names in RULE_SAMPLE.items():
            for name in names:
                seen.add(name)
                sample = first_payload(providers[name]["url"])
                self.assertEqual(providers[name]["behavior"], behavior)
                self.assertEqual(providers[name]["format"], "yaml")
                self.assertEqual(providers[name]["proxy"], "DIRECT")
                if behavior == "domain":
                    self.assertNotIn(",", sample)
                elif behavior == "classical":
                    self.assertTrue(sample.startswith("DOMAIN") or sample.startswith("PROCESS-NAME"), sample)
                else:
                    self.assertIn("/", sample)
        self.assertEqual(seen, set(providers))

    def test_mihomo_parses_generated_config(self):
        if not MIHOMO.is_file() or not os.access(MIHOMO, os.X_OK):
            self.skipTest("mihomo binary is not available")
        config = build(
            self.template,
            [
                node("花云-入口", "192.0.2.1", 1001, type="ss"),
                node("自建-入口", "192.0.2.2", 1002, type="trojan"),
                node(
                    "落地-出口",
                    "192.0.2.10",
                    2001,
                    type="vmess",
                    uuid="00000000-0000-4000-8000-000000000000",
                    alterId=0,
                    cipher="auto",
                ),
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "chain.yaml"
            path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
            result = subprocess.run(
                [str(MIHOMO), "-t", "-f", str(path)],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=180,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        combined = result.stdout + result.stderr
        self.assertNotIn("192.0.2.10:2001", combined)
        self.assertIn("test is successful", combined)

    def assert_acyclic(self, config):
        groups = {item["name"]: item for item in config["proxy-groups"]}
        proxies = {item["name"]: item for item in config["proxies"]}
        builtins = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
        visiting = set()

        def walk(name, stack):
            if name in visiting:
                self.fail("cycle: " + " -> ".join(stack + [name]))
            visiting.add(name)
            for member in groups[name].get("proxies") or []:
                if member in groups:
                    walk(member, stack + [name])
                elif member not in builtins:
                    self.assertIn(member, proxies)
                    dialer = proxies[member].get("dialer-proxy")
                    if dialer:
                        self.assertIn(dialer, groups)
                        walk(dialer, stack + [name, member])
            visiting.remove(name)

        for name in groups:
            walk(name, [])

    def assert_rule_priority(self, rules):
        def position(prefix):
            return next(index for index, rule in enumerate(rules) if rule.startswith(prefix))

        self.assertTrue(rules[0].startswith("RULE-SET,private,"))
        self.assertTrue(rules[-1].startswith("MATCH,漏网之鱼"))
        self.assertLess(position("RULE-SET,private,"), position("RULE-SET,ads,"))
        self.assertLess(position("RULE-SET,ads,"), position("RULE-SET,ai,"))
        self.assertLess(position("RULE-SET,ai,"), position("RULE-SET,google,"))
        self.assertLess(position("RULE-SET,games-cn,"), position("RULE-SET,games,"))
        self.assertLess(position("RULE-SET,finance,"), position("RULE-SET,gfw,"))
        self.assertLess(position("RULE-SET,crypto,"), position("RULE-SET,gfw,"))
        self.assertLess(position("RULE-SET,gfw,"), position("RULE-SET,cn-domain,"))
        self.assertLess(position("RULE-SET,telegram-ip,"), position("GEOIP,CN,"))
        targets = []
        for rule in rules:
            parts = [part.strip() for part in rule.split(",")]
            if parts[-1] == "no-resolve":
                parts.pop()
            targets.append(parts[-1])
        known = {item["name"] for item in self.template["proxy-groups"]} | {"DIRECT", "REJECT"}
        self.assertTrue(set(targets) <= known)


def first_payload(url):
    request = urllib.request.Request(url, headers={"User-Agent": "chain-mihomo-test"})
    with urllib.request.urlopen(request, timeout=40) as response:
        data = response.read(500).decode("utf-8", "replace")
    for line in data.splitlines():
        text = line.strip()
        if not text or text.startswith("#") or text == "payload:":
            continue
        return text.lstrip("-").strip().strip("'\"")
    raise AssertionError("no payload item in " + url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
