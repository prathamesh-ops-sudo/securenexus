import { registerPlugin } from "./connector-plugin";

import { crowdstrikePlugin } from "./crowdstrike";
import { splunkPlugin } from "./splunk";
import { wizPlugin } from "./wiz";
import { wazuhPlugin } from "./wazuh";
import { paloaltoPlugin } from "./paloalto";
import { guarddutyPlugin } from "./guardduty";
import { defenderPlugin } from "./defender";
import { sentinelonePlugin } from "./sentinelone";
import { elasticPlugin } from "./elastic";
import { qradarPlugin } from "./qradar";
import { fortigatePlugin } from "./fortigate";
import { carbonblackPlugin } from "./carbonblack";
import { qualysPlugin } from "./qualys";
import { tenablePlugin } from "./tenable";
import { umbrellaPlugin } from "./umbrella";
import { darktracePlugin } from "./darktrace";
import { rapid7Plugin } from "./rapid7";
import { trendmicroPlugin } from "./trendmicro";
import { oktaPlugin } from "./okta";
import { proofpointPlugin } from "./proofpoint";
import { snortPlugin } from "./snort";
import { zscalerPlugin } from "./zscaler";
import { checkpointPlugin } from "./checkpoint";

const ALL_PLUGINS = [
  crowdstrikePlugin,
  splunkPlugin,
  wizPlugin,
  wazuhPlugin,
  paloaltoPlugin,
  guarddutyPlugin,
  defenderPlugin,
  sentinelonePlugin,
  elasticPlugin,
  qradarPlugin,
  fortigatePlugin,
  carbonblackPlugin,
  qualysPlugin,
  tenablePlugin,
  umbrellaPlugin,
  darktracePlugin,
  rapid7Plugin,
  trendmicroPlugin,
  oktaPlugin,
  proofpointPlugin,
  snortPlugin,
  zscalerPlugin,
  checkpointPlugin,
] as const;

let initialized = false;

export function initializeConnectorPlugins(): void {
  if (initialized) return;
  for (const plugin of ALL_PLUGINS) {
    registerPlugin(plugin);
  }
  initialized = true;
}

export const PLUGIN_COUNT = ALL_PLUGINS.length;
