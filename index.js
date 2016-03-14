'use strict';

module.exports = {
  handler: {
    install(sink) {
      Process.setExceptionHandler(exception => {
        sink.onPanic(preparePanic(exception.message, exception, exception.context));
      });

      if (Process.platform === 'darwin') {
        const objcThrow = Module.findExportByName('libobjc.A.dylib', 'objc_exception_throw');
        if (objcThrow !== null) {
          let potentialObjCPanic = null;

          Interceptor.attach(objcThrow, {
            onEnter(args) {
              const exception = new ObjC.Object(args[0]);
              potentialObjCPanic = preparePanic('Unhandled Objective-C exception: ' + exception.toString(), {}, this.context);
            }
          });

          Interceptor.attach(Module.findExportByName('libsystem_c.dylib', 'abort'), {
            onEnter(args) {
              const isCausedByUnhandledObjCException = Thread.backtrace(this.context).map(DebugSymbol.fromAddress).some(symbol => {
                return symbol.moduleName === 'libobjc.A.dylib' && symbol.name === '_objc_terminate()';
              });
              if (isCausedByUnhandledObjCException)
                sink.onPanic(potentialObjCPanic);
            }
          });
        }
      }

      function preparePanic(message, details, cpuContext) {
        const backtrace = Thread.backtrace(cpuContext).map(DebugSymbol.fromAddress);

        return {
          message: message,
          details: details,
          stack: {
            native: backtrace.map(frame => frame.toString()).join('\n'),
            js: new Error().stack
          }
        };
      }
    }
  },
  format(error) {
    return `********************************************************************************
${error.message}

Native stack:
${'\t' + error.stack.native.replace(/\n/g, '\n\t')}

JavaScript stack:
${'\t' + error.stack.js.replace(/\n/g, '\n\t')}

Details:
${'\t' + JSON.stringify(error.details, null, 4).replace(/\n/g, '\n\t')}
********************************************************************************
`;
  }
};
