'use strict';

const unsafeOperations = {};

module.exports = {
  handler: {
    install(sink) {
      Process.setExceptionHandler(exception => {
        sink.onPanic(preparePanic(exception.message, exception, exception.context));
      });

      if (Process.platform === 'darwin') {
        const objcThrow = Module.findExportByName('libobjc.A.dylib', 'objc_exception_throw');
        let potentialObjCPanic = null;
        const cppThrowSystemError = Module.findExportByName('libc++.1.dylib', '_ZNSt3__120__throw_system_errorEiPKc');
        let potentialCPPPanic = null;

        if (objcThrow !== null) {

          Interceptor.attach(objcThrow, function (args) {
            const exception = new ObjC.Object(args[0]);
            const description = exception.toString();
            potentialObjCPanic = {
              description: description,
              details: preparePanic(`Unhandled Objective-C exception: ${description}`, {}, this.context)
            };
          });
        }

        if (cppThrowSystemError !== null) {

          Interceptor.attach(cppThrowSystemError, function (args) {
            const description = args[1].isNull() ? '' : Memory.readUtf8String(args[1]);
            potentialCPPPanic = {
              description: description,
              details: preparePanic(`Unhandled C++ exception: ${description}`, {}, this.context)
            };
          });
        }

        if (objcThrow !== null || cppThrowSystemError !== null) {

          Interceptor.attach(Module.findExportByName('libsystem_c.dylib', 'abort'), {
            onEnter(args) {
              const symbols = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
              const isCausedByUnhandledObjCException = symbols.some(symbol => {
                return symbol.moduleName === 'libobjc.A.dylib' && symbol.name === '_objc_terminate()';
              });
              const isCausedByCPPException = symbols.some(symbol => {
                return symbol.moduleName === 'libc++.1.dylib' && symbol.name === 'std::__1::__throw_system_error(int, char const*)';
              });
              if (isCausedByUnhandledObjCException) {
                const details = unsafeOperations[Process.getCurrentThreadId()];
                if (details !== undefined) {
                  details.exception = new Error(potentialObjCPanic.description);
                } else if (potentialObjCPanic) {
                  sink.onPanic(potentialObjCPanic.details);
                }
              }
              if (isCausedByCPPException) {
                const details = unsafeOperations[Process.getCurrentThreadId()];
                if (details !== undefined) {
                  details.exception = new Error(potentialCPPPanic.description);
                } else if (potentialCPPPanic) {
                  sink.onPanic(potentialCPPPanic.details);
                }
              }
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
            js: new Error().stack,
            raw: digStack(cpuContext).join('\n')
          }
        };
      }

      function digStack(cpuContext) {
        const manualTrace = [];

        for (let i = 0; i !== 128; i++) {
          try {
            const addr = Memory.readPointer(cpuContext.sp.add(i * Process.pointerSize));
            manualTrace.push(
              DebugSymbol.fromAddress(addr).toString()
            );
          } catch(e) {
          }
        }

        return manualTrace;
      }
    }
  },
  performUnsafeOperation(operation) {
    const threadId = Process.getCurrentThreadId();

    const details = {
      exception: null
    };
    unsafeOperations[threadId] = details;

    try {
      return operation();
    } catch (e) {
      if (details.exception !== null)
        throw details.exception;
      else
        throw e;
    } finally {
      delete unsafeOperations[threadId];
    }
  },
  format(error) {
    return `********************************************************************************
${error.message}

Native stack:
${'\t' + error.stack.native.replace(/\n/g, '\n\t')}

JavaScript stack:
${'\t' + error.stack.js.replace(/\n/g, '\n\t')}

Raw stack:
${'\t' + error.stack.raw.replace(/\n/g, '\n\t')}

Details:
${'\t' + JSON.stringify(error.details, null, 4).replace(/\n/g, '\n\t')}
********************************************************************************
`;
  }
};
