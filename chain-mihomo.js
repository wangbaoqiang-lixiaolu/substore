// Clash Party 与 FlClash 共用的 Sub-Store 文件脚本。
// 用法见 chain-mihomo-指南.md。只改下面 CHAIN 里的名称。
//
// 这是唯一的集成方式：Sub-Store 的文件类型必须是 mihomo 配置。
// 保存文件时，Sub-Store 会调用 main(config)，并把返回的完整对象写成 YAML。
// 脚本自己用 produceArtifact 读取入口和出口，不要再添加「从订阅添加节点」。

var CHAIN = {
  // type 只能是 "subscription"（单条订阅）或 "collection"（组合订阅）。
  // name 必须与 Sub-Store 里的名称完全一致。
  entrance: { type: "subscription", name: "入口" },
  exit: { type: "subscription", name: "出口" },
  entranceGroup: "入口选择",
  exitGroup: "出口选择",
  entranceMark: "入口·",
  exitMark: "出口·",
};

var GROUP = {
  entrance: "入口选择",
  exit: "出口选择",
  main: "默认代理",
  ai: "AI 服务",
  social: "消息与社交",
  media: "流媒体与音乐",
  games: "游戏",
  dev: "开发与 GitHub",
  microsoft: "微软服务",
  apple: "苹果服务",
  google: "谷歌服务",
  finance: "金融服务",
  ads: "广告拦截",
  downloads: "下载与工具",
  domestic: "国内与局域网",
  final: "漏网之鱼",
};

var BUILTIN = {
  DIRECT: true,
  REJECT: true,
  "REJECT-DROP": true,
  PASS: true,
  COMPATIBLE: true,
};

var BLOCKED_EXIT_TYPE = {
  hysteria: "Hysteria 使用 UDP，入口节点转发不了",
  hysteria2: "Hysteria2 使用 QUIC/UDP，入口节点转发不了",
  hy2: "Hysteria2 使用 QUIC/UDP，入口节点转发不了",
  tuic: "TUIC 使用 QUIC/UDP，入口节点转发不了",
  wireguard: "WireGuard 不能作为被入口转发的出口",
  wg: "WireGuard 不能作为被入口转发的出口",
  shadowtls: "ShadowTLS 不能作为被入口转发的出口",
  anytls: "AnyTLS 不能作为被入口转发的出口",
  mieru: "Mieru 不能作为被入口转发的出口",
  sudoku: "Sudoku 不能作为被入口转发的出口",
  tailscale: "Tailscale 不能作为被入口转发的出口",
  ssh: "SSH 不能作为被入口转发的出口",
  easytier: "EasyTier 不能作为被入口转发的出口",
  openvpn: "OpenVPN 不能作为被入口转发的出口",
  gost: "GOST 不能作为被入口转发的出口",
  shadowquic: "ShadowQUIC 使用 UDP，入口节点转发不了",
  masque: "MASQUE 不能作为被入口转发的出口",
  zerotier: "ZeroTier 不能作为被入口转发的出口",
};

var CHAIN_DEFAULT_GROUPS = [
  GROUP.main,
  GROUP.ai,
  GROUP.social,
  GROUP.media,
  GROUP.games,
  GROUP.dev,
  GROUP.microsoft,
  GROUP.apple,
  GROUP.google,
];

function buildChainConfig(config, entranceProxies, exitProxies) {
  const next = JSON.parse(JSON.stringify(config || null));
  if (CHAIN.entranceGroup !== GROUP.entrance || CHAIN.exitGroup !== GROUP.exit) {
    throw new Error("脚本内部的入口或出口组名不一致。");
  }
  if (!next || typeof next !== "object" || Array.isArray(next)) {
    throw new Error("配置模板是空的。请把 chain-mihomo.yaml 作为 mihomo 文件的内容。");
  }
  const groups = next["proxy-groups"];
  if (!Array.isArray(groups)) {
    throw new Error("模板缺少 proxy-groups。请使用 chain-mihomo.yaml 的完整内容。");
  }
  assertPolicyShape(groups);

  const entrance = normalizeSide(entranceProxies, "入口", CHAIN.entranceMark);
  const exit = normalizeSide(exitProxies, "出口", CHAIN.exitMark);
  rejectBlockedExits(exit);
  rejectSharedEndpoints(entrance, exit);

  const used = Object.create(null);
  const entranceReady = tagSide(entrance, CHAIN.entranceMark, used, null);
  const exitReady = tagSide(exit, CHAIN.exitMark, used, CHAIN.entranceGroup);

  next.proxies = entranceReady.concat(exitReady);
  fillMembers(groups, CHAIN.entranceGroup, entranceReady.map(item => item.name));
  fillMembers(groups, CHAIN.exitGroup, exitReady.map(item => item.name));
  assertReferences(next);
  return next;
}

async function main(config) {
  if (typeof produceArtifact !== "function") {
    throw new Error("这个脚本只能作为 Sub-Store mihomo 配置文件的脚本操作运行。");
  }
  if (
    CHAIN.entrance.type === CHAIN.exit.type &&
    CHAIN.entrance.name === CHAIN.exit.name
  ) {
    throw new Error("入口和出口不能填写同一个订阅。请分成两份来源。");
  }
  const entrance = await loadRole(CHAIN.entrance, "入口");
  const exit = await loadRole(CHAIN.exit, "出口");
  return buildChainConfig(config, entrance, exit);
}

async function loadRole(spec, role) {
  if (!spec || !spec.name || !spec.type) {
    throw new Error("请在脚本顶部填写" + role + "的 type 和 name。");
  }
  if (spec.type !== "subscription" && spec.type !== "collection") {
    throw new Error(role + "的 type 只能是 subscription 或 collection。");
  }
  let proxies;
  try {
    proxies = await produceArtifact({
      type: spec.type,
      name: spec.name,
      platform: "mihomo",
      produceType: "internal",
    });
  } catch (error) {
    const reason = error && error.message ? error.message : String(error);
    throw new Error(
      "读不到" +
        role +
        "「" +
        spec.name +
        "」（" +
        spec.type +
        "）。请把 CHAIN 里的 name 改成 Sub-Store 中完全相同的名字；它如果是组合订阅，把 type 改成 collection。原始错误：" +
        reason
    );
  }
  if (!Array.isArray(proxies) || proxies.length === 0) {
    throw new Error(role + "「" + spec.name + "」里没有节点。");
  }
  return proxies;
}

function assertPolicyShape(groups) {
  const byName = indexGroups(groups);
  Object.keys(GROUP).forEach(key => {
    if (!byName[GROUP[key]]) {
      throw new Error("模板缺少策略组「" + GROUP[key] + "」。请不要重命名策略组。");
    }
  });
  groups.forEach(group => {
    if (group.type !== "select") {
      throw new Error("策略组「" + group.name + "」必须是 select，不能自动切换节点。");
    }
  });
  CHAIN_DEFAULT_GROUPS.forEach(name => {
    const first = byName[name].proxies && byName[name].proxies[0];
    if (first !== CHAIN.exitGroup) {
      throw new Error("「" + name + "」的第一项必须是「" + CHAIN.exitGroup + "」，避免默认直连或自动换节点。");
    }
    assertManualMembers(byName[name], byName);
  });
  const finalFirst = byName[GROUP.final].proxies && byName[GROUP.final].proxies[0];
  if (finalFirst !== GROUP.main) {
    throw new Error("「漏网之鱼」的第一项必须是「默认代理」。");
  }
  assertManualMembers(byName[GROUP.final], byName);
  assertFirst(byName[GROUP.finance], "DIRECT");
  assertFirst(byName[GROUP.domestic], "DIRECT");
  assertFirst(byName[GROUP.downloads], "DIRECT");
  assertFirst(byName[GROUP.ads], "REJECT");
}

function assertFirst(group, expected) {
  const first = group.proxies && group.proxies[0];
  if (first !== expected) {
    throw new Error("「" + group.name + "」的第一项必须是 " + expected + "。");
  }
}

function assertManualMembers(group, byName) {
  (group.proxies || []).forEach(member => {
    if (member === "DIRECT" || member === "REJECT" || byName[member]) return;
    throw new Error(
      "「" + group.name + "」只能选择策略组、直连或拒绝，不能直接放入单个节点「" + member + "」。"
    );
  });
}

function normalizeSide(list, role, mark) {
  if (!Array.isArray(list) || list.length === 0) {
    throw new Error(role + "没有节点。请检查对应订阅，或修改脚本顶部的名称。");
  }
  return list.map((proxy, index) => {
    if (!proxy || typeof proxy !== "object" || Array.isArray(proxy)) {
      throw new Error(role + "第 " + (index + 1) + " 个节点不是有效对象。");
    }
    if (!proxy.name) {
      throw new Error(role + "第 " + (index + 1) + " 个节点没有名称。");
    }
    if (!proxy.server || proxy.port === undefined || proxy.port === null || proxy.port === "") {
      throw new Error("节点「" + proxy.name + "」缺少服务器或端口。");
    }
    const copy = {};
    Object.keys(proxy).forEach(key => {
      if (key.charAt(0) !== "_") copy[key] = proxy[key];
    });
    copy.name = stripMark(String(copy.name), mark);
    delete copy["dialer-proxy"];
    delete copy["underlying-proxy"];
    return copy;
  });
}

function stripMark(name, preferred) {
  let current = name;
  let removedMark = false;
  const marks = [CHAIN.entranceMark, CHAIN.exitMark, preferred];
  for (let round = 0; round < 4; round += 1) {
    const hit = marks.find(mark => mark && current.indexOf(mark) === 0);
    if (!hit) break;
    current = current.slice(hit.length);
    removedMark = true;
  }
  // 只去掉脚本自己加过的「 #2」。订阅里原有的同名后缀保留。
  if (removedMark) current = current.replace(/ #\d+$/, "");
  return current;
}

function rejectBlockedExits(proxies) {
  const problems = [];
  proxies.forEach(proxy => {
    const type = String(proxy.type || "").toLowerCase();
    const reason = BLOCKED_EXIT_TYPE[type] || realityReason(proxy) || pluginReason(proxy);
    if (reason) problems.push("「" + proxy.name + "」类型 " + (proxy.type || "未知") + "：" + reason);
  });
  if (problems.length === 0) return;
  const shown = problems.slice(0, 30).join("\n");
  const more = problems.length > 30 ? "\n其余 " + (problems.length - 30) + " 个未列出。" : "";
  throw new Error(
    "出口里有链式代理无法转发的节点，已停止生成，避免这些节点看起来可用。\n" +
      shown +
      more +
      "\n请把这些节点移出出口来源，或改用 SS、SSR、VMess、Trojan、无 REALITY 的 VLESS、HTTP、SOCKS5、Snell。" +
      "\nHysteria、Hysteria2、TUIC、WireGuard、REALITY、ShadowTLS、AnyTLS 以及其他 UDP 或专有隧道协议不能作为被入口转发的出口。" +
      "\n允许的协议也只保证 TCP；经过入口后的 UDP（例如部分语音通话）没有保证。"
  );
}

function realityReason(proxy) {
  if (proxy["reality-opts"] || proxy["reality-config"] || proxy.reality) {
    return "REALITY 不能被普通入口节点转发";
  }
  return "";
}

function pluginReason(proxy) {
  const plugin = String(proxy.plugin || proxy.obfs || "").toLowerCase();
  if (plugin.indexOf("shadowtls") !== -1 || plugin.indexOf("restls") !== -1 || plugin.indexOf("reality") !== -1) {
    return "插件 " + (proxy.plugin || proxy.obfs) + " 不能作为被入口转发的出口";
  }
  return "";
}

function rejectSharedEndpoints(entrance, exit) {
  const seen = {};
  entrance.forEach(proxy => {
    seen[endpointOf(proxy)] = proxy.name;
  });
  exit.forEach(proxy => {
    const key = endpointOf(proxy);
    if (seen[key]) {
      throw new Error(
        "入口「" + seen[key] + "」和出口「" + proxy.name + "」使用了同一个服务器和端口。请只把这个节点放在其中一边。"
      );
    }
  });
}

function endpointOf(proxy) {
  return String(proxy.server).toLowerCase() + ":" + String(proxy.port);
}

function tagSide(proxies, mark, used, dialer) {
  return proxies.map(proxy => {
    const name = uniqueName(mark + proxy.name, used);
    proxy.name = name;
    if (dialer) proxy["dialer-proxy"] = dialer;
    else delete proxy["dialer-proxy"];
    if (BUILTIN[name]) {
      throw new Error("节点名称「" + name + "」与内置策略冲突。");
    }
    return proxy;
  });
}

function uniqueName(base, used) {
  let name = base;
  let number = 2;
  while (Object.prototype.hasOwnProperty.call(used, name)) {
    name = base + " #" + number;
    number += 1;
  }
  used[name] = true;
  return name;
}

function fillMembers(groups, groupName, members) {
  const group = groups.find(item => item && item.name === groupName);
  if (!group) throw new Error("模板缺少策略组「" + groupName + "」。");
  if (members.length === 0) {
    throw new Error("「" + groupName + "」没有可加入的节点。");
  }
  group.type = "select";
  group.proxies = members.slice();
  group["empty-fallback"] = "REJECT";
  delete group["include-all"];
  delete group["include-all-proxies"];
  delete group["include-all-providers"];
  delete group.filter;
  delete group["exclude-filter"];
  delete group["dialer-proxy"];
  delete group.use;
}

function indexGroups(groups) {
  const byName = {};
  groups.forEach(group => {
    if (!group || !group.name) throw new Error("存在没有名称的策略组。");
    if (byName[group.name]) throw new Error("策略组名称重复：「" + group.name + "」。");
    byName[group.name] = group;
  });
  return byName;
}

function assertReferences(config) {
  const groups = config["proxy-groups"];
  const byName = indexGroups(groups);
  const proxyNames = {};
  (config.proxies || []).forEach(proxy => {
    if (proxyNames[proxy.name]) throw new Error("节点名称重复：「" + proxy.name + "」。");
    if (byName[proxy.name] || BUILTIN[proxy.name]) {
      throw new Error("节点「" + proxy.name + "」与策略组或内置策略重名。");
    }
    proxyNames[proxy.name] = proxy;
  });

  const entrance = byName[CHAIN.entranceGroup];
  const exit = byName[CHAIN.exitGroup];
  entrance.proxies.forEach(name => {
    const proxy = proxyNames[name];
    if (!proxy) throw new Error("入口组引用了不存在的节点「" + name + "」。");
    if (proxy["dialer-proxy"]) {
      throw new Error("入口节点「" + name + "」不应再设置 dialer-proxy。");
    }
  });
  exit.proxies.forEach(name => {
    const proxy = proxyNames[name];
    if (!proxy) throw new Error("出口组引用了不存在的节点「" + name + "」。");
    if (proxy["dialer-proxy"] !== CHAIN.entranceGroup) {
      throw new Error("出口节点「" + name + "」必须经由「" + CHAIN.entranceGroup + "」连出。");
    }
  });

  Object.keys(proxyNames).forEach(name => {
    const dialer = proxyNames[name]["dialer-proxy"];
    if (!dialer) return;
    if (dialer === name || proxyNames[dialer]) {
      throw new Error("节点「" + name + "」的 dialer-proxy 不能指向另一个节点。");
    }
    if (!byName[dialer]) throw new Error("节点「" + name + "」的 dialer-proxy「" + dialer + "」不存在。");
    if (dialer !== CHAIN.entranceGroup) {
      throw new Error("节点「" + name + "」只能经由「" + CHAIN.entranceGroup + "」。");
    }
  });

  const visiting = {};
  const visited = {};
  Object.keys(byName).forEach(name => walkGroup(name, byName, proxyNames, visiting, visited, []));

  (config.rules || []).forEach((rule, index) => {
    const target = ruleTarget(rule);
    if (!byName[target] && !BUILTIN[target]) {
      throw new Error("第 " + (index + 1) + " 条规则指向了不存在的目标「" + target + "」。");
    }
  });
  (config["rule-providers"] ? Object.keys(config["rule-providers"]) : []).forEach(name => {
    const provider = config["rule-providers"][name];
    if (!provider || !provider.url || !provider.behavior || !provider.format) {
      throw new Error("规则集「" + name + "」缺少 url、behavior 或 format。");
    }
  });
}

function walkGroup(name, byName, proxyNames, visiting, visited, stack) {
  if (visited[name]) return;
  if (visiting[name]) {
    throw new Error("策略组存在循环：" + stack.concat(name).join(" → "));
  }
  visiting[name] = true;
  const group = byName[name];
  (group.proxies || []).forEach(member => {
    if (byName[member]) {
      walkGroup(member, byName, proxyNames, visiting, visited, stack.concat(name));
      return;
    }
    if (BUILTIN[member]) return;
    const proxy = proxyNames[member];
    if (!proxy) throw new Error("策略组「" + name + "」引用了不存在的「" + member + "」。");
    const dialer = proxy["dialer-proxy"];
    if (dialer && byName[dialer]) {
      walkGroup(dialer, byName, proxyNames, visiting, visited, stack.concat(name, member));
    }
  });
  visiting[name] = false;
  visited[name] = true;
}

function ruleTarget(rule) {
  const parts = String(rule).split(",").map(part => part.trim()).filter(Boolean);
  if (parts.length < 2) throw new Error("无法识别规则：" + rule);
  if (parts[parts.length - 1] === "no-resolve") parts.pop();
  return parts[parts.length - 1];
}
