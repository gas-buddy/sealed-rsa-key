import repl from 'repl';

export default async function run() {
  return new Promise((accept) => {
    repl.start({
      prompt: 'sealed-rsa-key>',
      eval(cmd, context, filename, callback) {
        process.nextTick(callback);
      }
    });
  });
}
