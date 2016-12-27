import fs from 'fs';
import readline from 'readline';

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
    console.log(`Writing ${fn}`);
    fs.writeFile(fn, content, (error) => {
      if (error) {
        reject(error);
      } else {
        console.log(`Wrote ${fn}`);
        accept();
      }
    });
  });
}

export async function read(fn) {
  return new Promise((accept, reject) => {
    console.log(`Reading ${fn}`);
    fs.readFile(fn, (error, content) => {
      if (error) {
        reject(error);
      } else {
        console.log(`Read ${fn}`);
        accept(content);
      }
    });
  });
}

export async function hiddenPrompt(rl, query) {
  return new Promise((accept, reejct) => {
    const stdin = process.openStdin();
    const onDataHandler = function (char) {
      char = `${char}`;
      switch (char) {
        case '\n': case '\r': case '\u0004':
          // Remove this handler
          stdin.removeListener('data', onDataHandler);
          break;//stdin.pause(); break;
        default:
          process.stdout.write(`\x1B[2K\x1B[200D${query}${Array(rl.line.length + 1).join('*')}`);
          break;
      }
    }
    process.stdin.on('data', onDataHandler);

    rl.question(query, function (value) {
      rl.history = rl.history.slice(1);
      accept(value);
    });
  });
}
