<template>
  <section class="p-6 h-full overflow-auto">
    <div class="max-w-5xl mx-auto space-y-6">
      <header>
        <h2 class="text-3xl font-bold text-white">Proxy</h2>
        <p class="text-gray-400">Manage interception, upstream routing, and traffic capture.</p>
      </header>

      <div class="grid gap-4 md:grid-cols-3">
        <article class="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <p class="text-sm text-gray-400">Status</p>
          <p class="text-xl text-green-400 font-semibold">Stopped</p>
        </article>
        <article class="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <p class="text-sm text-gray-400">Listen Address</p>
          <p class="text-xl text-white font-semibold">127.0.0.1:8080</p>
        </article>
        <article class="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <p class="text-sm text-gray-400">Intercept Mode</p>
          <p class="text-xl text-white font-semibold">Ready</p>
        </article>
      </div>
    </div>
  </section>
</template>
