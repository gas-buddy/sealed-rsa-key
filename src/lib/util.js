import fs from 'fs';
import path from 'path';
import nconf from 'nconf';

let logger = console;

export function setLogger(l) {
  logger = l;
}

export function kbPath(...parts) {
  return path.join(nconf.get('kbfsroot'), 'private', ...parts);
}

export async function exists(fn) {
  return await new Promise((accept) => {
    fs.access(fn, (err) => {
      if (err) {
        accept(false);
      } else {
        accept(true);
      }
    });
  });
}

export async function write(fn, content) {
  return new Promise((accept, reject) => {
    logger.log(`Writing ${fn}`);
    fs.writeFile(fn, content, (error) => {
      if (error) {
        reject(error);
      } else {
        accept();
      }
    });
  });
}

export async function read(fn) {
  return new Promise((accept, reject) => {
    logger.log(`Reading ${fn}`);
    fs.readFile(fn, (error, content) => {
      if (error) {
        reject(error);
      } else {
        accept(content);
      }
    });
  });
}

export async function hiddenPrompt(rl, query) {
  return new Promise((accept) => {
    const stdin = process.openStdin();
    const onDataHandler = function onDataHandler(char) {
      switch (`${char}`) {
        case '\n': case '\r': case '\u0004':
          // Remove this handler
          stdin.removeListener('data', onDataHandler);
          break;
        default:
          process.stdout.write(`\x1B[2K\x1B[200D${query}${Array(rl.line.length + 1).join('*')}`);
          break;
      }
    };
    process.stdin.on('data', onDataHandler);

    rl.question(query, (value) => {
      rl.history = rl.history.slice(1);
      accept(value);
    });
  });
}
