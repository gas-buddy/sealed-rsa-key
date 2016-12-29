import nconf from 'nconf';

export function getKeymasters(argValue, callback) {
  const keymasters = argValue || nconf.get('keymasters');
  if (!keymasters) {
    callback('Missing keymasters argument - must be a comma separate list of keybase ids');
    return null;
  }
  return keymasters.split(',');
}

export function parseKeymaster(keymaster) {
  const m = keymaster.match(/([^#]+)#?(.*)/);
  let folderName = nconf.get('me');
  if (folderName !== m[1]) {
    folderName = [folderName, m[1]].join(',');
  }
  return {
    folderName,
    hash: m[2],
    suffix: m[2] ? `.${m[2]}` : '',
  };
}
