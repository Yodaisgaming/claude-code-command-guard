'use strict';

const database = [
  { id: 'db_drop', tier: 'block', pattern: /\bdrop\s+(?:database|table|schema|index)\b/i, note: 'DROP destroys a database object' },
  { id: 'db_truncate', tier: 'block', pattern: /\btruncate\s+(?:table\s+)?[`"'\[]?[\w.]+/i, note: 'TRUNCATE empties a table' },
  { id: 'db_dropdb', tier: 'block', pattern: /\bdropdb\b/i, note: 'dropdb removes a database' },
  { id: 'db_flush', tier: 'block', pattern: /\b(?:flushall|flushdb)\b/i, note: 'Redis FLUSHALL/FLUSHDB wipes keys' },
];

const device = [
  { id: 'dev_dd', tier: 'block', pattern: /\bdd\b[^|&;\n]*\bof=\/dev\//i, note: 'dd writing to a raw device destroys it' },
  { id: 'dev_mkfs', tier: 'block', pattern: /\bmkfs(?:\.\w+)?\b/i, note: 'mkfs formats a filesystem' },
  { id: 'dev_shred', tier: 'block', pattern: /\bshred\s+\S/i, note: 'shred irreversibly wipes files' },
  { id: 'dev_truncate_zero', tier: 'block', pattern: /\btruncate\s+(?:-s\s*0|--size[= ]0)\b/i, note: 'truncate to zero empties a file' },
  { id: 'dev_overwrite_device', tier: 'block', pattern: />\s*\/dev\/(?:sd|nvme|hd|disk)/i, note: 'redirect into a raw device' },
];

const windowsStorage = [
  { id: 'win_format_volume', tier: 'block', pattern: /\bformat-volume\b/i, note: 'Format-Volume formats a drive' },
  { id: 'win_format_drive', tier: 'block', pattern: /\bformat\s+[a-z]:/i, note: 'format X: formats a drive' },
  { id: 'win_diskpart', tier: 'block', pattern: /\bdiskpart\b/i, note: 'diskpart can wipe partitions' },
  { id: 'win_vssadmin', tier: 'block', pattern: /\bvssadmin\s+delete\b/i, note: 'vssadmin delete removes shadow copies (ransomware pattern)' },
];

const windowsOps = [
  { id: 'win_reg_delete', tier: 'ask', pattern: /\breg\s+delete\b/i, note: 'reg delete removes registry keys' },
  { id: 'win_sc_delete', tier: 'ask', pattern: /\bsc\s+(?:delete|stop)\b/i, note: 'sc delete/stop removes or halts a service' },
  { id: 'win_schtasks_delete', tier: 'ask', pattern: /\bschtasks\b[^|&;\n]*\/delete\b/i, note: 'schtasks /delete removes a scheduled task' },
  { id: 'win_shutdown', tier: 'ask', pattern: /\bshutdown(?=\s|$|\/)|\b(?:restart-computer|stop-computer)\b/i, note: 'shuts down or reboots the machine' },
];

const cloud = [
  { id: 'cloud_vercel_remove', tier: 'ask', pattern: /\bvercel\s+(?:remove|rm)\b/i, note: 'vercel remove deletes a deployment' },
  { id: 'cloud_railway_down', tier: 'ask', pattern: /\brailway\s+(?:down|delete)\b/i, note: 'railway down/delete tears down a service' },
  { id: 'cloud_cloudflare_delete', tier: 'ask', pattern: /\b(?:wrangler|cloudflare)\b[^|&;\n]*\bdelete\b/i, note: 'Cloudflare/wrangler delete' },
  { id: 'cloud_terraform', tier: 'ask', pattern: /\bterraform\s+(?:destroy|apply)\b/i, note: 'terraform destroy/apply mutates infra' },
  { id: 'cloud_kubectl_delete', tier: 'ask', pattern: /\bkubectl\s+delete\b/i, note: 'kubectl delete removes cluster resources' },
  { id: 'cloud_helm_delete', tier: 'ask', pattern: /\bhelm\s+(?:delete|uninstall)\b/i, note: 'helm delete/uninstall removes a release' },
  { id: 'cloud_docker_prune', tier: 'ask', pattern: /\bdocker\s+(?:system\s+|volume\s+|image\s+|container\s+)?prune\b/i, note: 'docker prune reclaims and deletes' },
  { id: 'cloud_aws_destructive', tier: 'ask', pattern: /\baws\s+[^|&;\n]*(?:delete-|terminate-|remove-|deregister-|\brb\b|\brm\b)/i, note: 'destructive aws CLI verb' },
  { id: 'cloud_gcloud_delete', tier: 'ask', pattern: /\bgcloud\s+[^|&;\n]*\bdelete\b/i, note: 'gcloud delete' },
  { id: 'cloud_az_delete', tier: 'ask', pattern: /\baz\s+[^|&;\n]*\bdelete\b/i, note: 'az delete' },
];

const obfuscation = [
  { id: 'obf_pipe_to_shell', tier: 'block', pattern: /\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[\s\S]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|node|perl)\b/i, note: 'download piped straight into a shell' },
  { id: 'obf_eval_base64', tier: 'block', pattern: /\beval\b[\s\S]*base64|\bbase64\b[\s\S]*(?:-d|--decode)[\s\S]*\|\s*(?:bash|sh|zsh)\b/i, note: 'eval of base64-decoded payload' },
  { id: 'obf_fork_bomb', tier: 'block', pattern: /\(\)\s*\{\s*[:\w.]+\s*\|\s*[:\w.]+\s*&\s*\}\s*;/, note: 'fork bomb' },
];

const packageSystem = [
  { id: 'pkg_chmod_777', tier: 'ask', pattern: /\bchmod\s+(?:-[a-z]*r[a-z]*\s+)?[0-7]*777\b/i, note: 'chmod 777 grants world-write' },
  { id: 'pkg_chmod_setuid', tier: 'ask', pattern: /\bchmod\s+(?:[0-7]?[4-7][0-7]{3}\b|[\s\S]*\+s\b)/i, note: 'chmod setuid bit' },
];

const bulkDelete = [
  { id: 'fs_find_delete', tier: 'ask', pattern: /\bfind\b[^|&;\n]*-delete\b/i, note: 'find -delete removes every match under an unknown scope' },
  { id: 'fs_find_exec_rm', tier: 'ask', pattern: /\bfind\b[^|&;\n]*-exec\s+rm\b/i, note: 'find -exec rm removes every match' },
  { id: 'fs_xargs_rm', tier: 'ask', pattern: /\bxargs\b[^|]*\brm\s+-[a-z]*[rf]/i, note: 'xargs piping into rm -rf' },
];

const wordpress = [
  { id: 'wp_db_drop', tier: 'block', pattern: /\bwp\s+db\s+(?:drop|reset|clean)\b/i, note: 'wp db drop/reset wipes the database' },
  { id: 'wp_site_empty', tier: 'block', pattern: /\bwp\s+site\s+empty\b/i, note: 'wp site empty deletes all content' },
];

const packs = { database, device, windowsStorage, windowsOps, cloud, obfuscation, packageSystem, bulkDelete, wordpress };

const RULES = [].concat(
  database, device, windowsStorage, obfuscation, wordpress,
  windowsOps, cloud, packageSystem, bulkDelete
);

const FALLBACK = [
  { id: 'fb_rm_rf', pattern: /\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)\b/i, note: 'rm -rf (fallback)' },
  { id: 'fb_git_reset_hard', pattern: /\bgit\s+reset\s+--hard\b/i, note: 'git reset --hard (fallback)' },
  { id: 'fb_force_push', pattern: /\bgit\s+push\b[\s\S]*(?:--force|\s-f\b|\s\+\w)/i, note: 'git force push (fallback)' },
  { id: 'fb_drop_truncate', pattern: /\b(?:drop\s+(?:database|table|schema)|truncate\s+table)\b/i, note: 'DROP/TRUNCATE (fallback)' },
  { id: 'fb_remove_item_recurse', pattern: /\bremove-item\b[\s\S]*-recurse\b/i, note: 'Remove-Item -Recurse (fallback)' },
  { id: 'fb_vssadmin', pattern: /\bvssadmin\s+delete\b/i, note: 'vssadmin delete (fallback)' },
  { id: 'fb_mkfs_dd', pattern: /\bmkfs\b|\bdd\b[\s\S]*of=\/dev\//i, note: 'mkfs / dd to device (fallback)' },
  { id: 'fb_flushall', pattern: /\bflushall\b/i, note: 'FLUSHALL (fallback)' },
  { id: 'fb_fork_bomb', pattern: /\(\)\s*\{\s*[:\w.]+\s*\|\s*[:\w.]+\s*&\s*\}\s*;/, note: 'fork bomb (fallback)' },
];

module.exports = { packs, RULES, FALLBACK };
