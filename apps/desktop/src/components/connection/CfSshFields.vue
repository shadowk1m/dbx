<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { setCfSshMode } from "@/lib/connection/cfSsh";
import type { SshTunnelConfig } from "@/types/database";

const props = defineProps<{ layer: SshTunnelConfig }>();
const { t } = useI18n();
</script>

<template>
  <div class="grid grid-cols-4 items-center gap-4">
    <Label class="text-xs">{{ t("connection.cfSshMode") }}</Label>
    <Select :model-value="layer.cf ? 'cf' : 'ssh'" :disabled="layer.enabled === false" @update:model-value="(value) => setCfSshMode(props.layer, value === 'cf')">
      <SelectTrigger class="col-span-3 h-9"><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value="ssh">SSH</SelectItem>
        <SelectItem value="cf">Cloud Foundry (SSO)</SelectItem>
      </SelectContent>
    </Select>
  </div>
  <template v-if="layer.cf">
    <div class="grid grid-cols-4 items-center gap-4">
      <Label class="text-xs">{{ t("connection.cfSsh_api_endpoint") }}</Label>
      <Input v-model="layer.cf!.api_endpoint" class="col-span-3" :disabled="layer.enabled === false" placeholder="https://api.cf.example.com" />
    </div>
    <div class="grid grid-cols-4 items-center gap-4">
      <Label class="text-xs">{{ t("connection.cfSsh_org") }}</Label>
      <Input v-model="layer.cf!.org" class="col-span-3" :disabled="layer.enabled === false" />
    </div>
    <div class="grid grid-cols-4 items-center gap-4">
      <Label class="text-xs">{{ t("connection.cfSsh_space") }}</Label>
      <Input v-model="layer.cf!.space" class="col-span-3" :disabled="layer.enabled === false" />
    </div>
    <div class="grid grid-cols-4 items-center gap-4">
      <Label class="text-xs">{{ t("connection.cfSsh_app") }}</Label>
      <Input v-model="layer.cf!.app" class="col-span-3" :disabled="layer.enabled === false" />
    </div>
    <div class="grid grid-cols-4 items-center gap-4">
      <Label class="text-xs">{{ t("connection.cfSshInstance") }}</Label>
      <Input v-model.number="layer.cf!.instance_index" class="col-span-3" type="number" min="0" max="4294967295" step="1" :disabled="layer.enabled === false" />
    </div>
    <p class="text-xs text-muted-foreground">{{ t("connection.cfSshHint") }}</p>
  </template>
</template>
