'use strict';

module.exports = {
  handler: {
    install(sink) {
      Process.setExceptionHandler(exception => {
        handlePanic(exception.message, exception, exception.context);
      });

      if (Process.platform === 'darwin') {
        const objcThrow = Module.findExportByName('libobjc.A.dylib', 'objc_exception_throw');
        if (objcThrow !== null) {
          Interceptor.attach(objcThrow, {
            onEnter(args) {
              const exception = new ObjC.Object(args[0]);
              handlePanic('Unhandled Objective-C exception: ' + exception.toString(), {}, this.context);
            }
          });
        }
      }

      function handlePanic(message, details, cpuContext) {
        const backtrace = Thread.backtrace(cpuContext).map(DebugSymbol.fromAddress);

        sink.onPanic({
          message: message,
          details: details,
          stack: {
            native: backtrace.map(frame => frame.toString()).join('\n'),
            js: new Error().stack
          }
        });
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
