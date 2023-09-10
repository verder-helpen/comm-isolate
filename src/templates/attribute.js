document.addEventListener("DOMContentLoaded", function() {
  const hostToken = window.location.pathname.split('/').pop();

  function listenForEvents() {
    const source = new EventSource(`live/${hostToken}`, { withCredentials: true });

    source.onmessage = (event) => {
      if (event.data && event.data === 'update') {
        source.close();
        window.location.reload();
      }
    };

    source.onerror = (e) => {
      source.close();
      console.error("EventSource failed:", e);
      setTimeout(listenForEvents, 5 * 1000);
    };
  }

  // poll until user is logged in
  listenForEvents();
});
