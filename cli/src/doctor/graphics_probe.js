(() => {
  const probe = (api) => {
    let renderer;
    try {
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = 4;
      let creationError = '';
      canvas.addEventListener('webglcontextcreationerror', (event) => {
        creationError = event.statusMessage;
      });
      const context = canvas.getContext(api);
      if (!context) {
        return { ok: false, detail: creationError || `${api} context is unavailable` };
      }

      let pixels;
      if (api === '2d') {
        context.fillStyle = '#ff0000';
        context.fillRect(0, 0, 4, 4);
        pixels = context.getImageData(2, 2, 1, 1).data;
      } else {
        const info = context.getExtension('WEBGL_debug_renderer_info');
        renderer = context.getParameter(info ? info.UNMASKED_RENDERER_WEBGL : context.RENDERER);
        context.clearColor(1, 0, 0, 1);
        context.clear(context.COLOR_BUFFER_BIT);
        pixels = new Uint8Array(4);
        context.readPixels(2, 2, 1, 1, context.RGBA, context.UNSIGNED_BYTE, pixels);
        const error = context.getError();
        if (error !== context.NO_ERROR || context.isContextLost()) {
          return { ok: false, detail: `WebGL error ${error}, context lost: ${context.isContextLost()}`, renderer };
        }
      }

      const detail = `rgba(${Array.from(pixels).join(',')})`;
      const ok = pixels[0] > 200 && pixels[1] < 64 && pixels[2] < 64 && pixels[3] > 200;
      return { ok, detail: ok ? detail : `expected opaque red, got ${detail}`, renderer };
    } catch (error) {
      return { ok: false, detail: String(error.message || error), renderer };
    }
  };

  return {
    canvas2d: probe('2d'),
    webgl: probe('webgl'),
    webgl2: probe('webgl2'),
  };
})()
