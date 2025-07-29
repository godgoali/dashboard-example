<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue';
import { Chart } from 'chart.js/auto';

const canvas = ref<HTMLCanvasElement | null>(null);
let chart: Chart | null = null;
let timer: NodeJS.Timer;

async function fetchData() {
  try {
    const res = await fetch('/scripts/metrics.js/trend/json');
    const data = await res.json();
    if (data.trend && data.trend.times) {
      const labels = data.trend.times.map((t: number) => new Date(t));
      const bps = data.trend.trends?.bps || [];
      if (!chart && canvas.value) {
        chart = new Chart(canvas.value.getContext('2d')!, {
          type: 'line',
          data: { labels, datasets: [{ label: 'Bps', data: bps }] },
          options: { scales: { y: { beginAtZero: true } } }
        });
      } else if (chart) {
        chart.data.labels = labels;
        chart.data.datasets[0].data = bps;
        chart.update();
      }
    }
  } catch(e) {
    console.error(e);
  }
}

onMounted(() => {
  fetchData();
  timer = setInterval(fetchData, 2000);
});

onBeforeUnmount(() => {
  clearInterval(timer);
  if (chart) chart.destroy();
});
</script>

<template>
  <canvas ref="canvas"></canvas>
</template>
