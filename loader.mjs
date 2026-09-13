export async function resolve(specifier, context, next) {
  if (specifier === 'protobufjs/minimal') specifier = 'protobufjs/minimal.js';
  return next(specifier, context);
}
