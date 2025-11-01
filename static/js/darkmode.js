// static/js/darkmode.js
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.darkmode-toggle');
    if (!toggle) return;

    const canvas = document.createElement('canvas');
    canvas.width = 44; canvas.height = 44;
    canvas.style.cursor = 'pointer';
    canvas.style.border = 'none';
    canvas.style.background = 'transparent';
    canvas.title = 'Toggle Dark/Light Mode';

    // Replace the button with canvas
    toggle.parentNode.replaceChild(canvas, toggle);

    const ctx = canvas.getContext('2d');
    let isDark = document.body.classList.contains('dark');
    let animating = false;
    let angle = 0;
    let drops = [];
    let splashes = [];

    function drawBucket() {
        ctx.clearRect(0, 0, 44, 44);
        ctx.save();
        ctx.translate(22, 38);
        ctx.rotate((-angle * Math.PI) / 180);
        ctx.translate(-22, -38);

        // Bucket body
        const bucketGradient = ctx.createLinearGradient(13, 12, 13, 34);
        bucketGradient.addColorStop(0, '#D6DDE2');
        bucketGradient.addColorStop(1, '#8A9AA3');
        ctx.fillStyle = bucketGradient;
        ctx.beginPath();
        ctx.roundRect(13, 12, 18, 24, 5);
        ctx.fill();

        // Rim
        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(14, 16);
        ctx.lineTo(30, 16);
        ctx.stroke();

        // Handle
        ctx.strokeStyle = '#607D8B';
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        ctx.moveTo(10, 18);
        ctx.quadraticCurveTo(7, 23, 10, 28);
        ctx.stroke();

        // Paint inside (current mode)
        const currentPaint = isDark ? '#000000' : '#FF9800';
        const paintGradient = ctx.createLinearGradient(15, 18, 15, 32);
        paintGradient.addColorStop(0, currentPaint);
        paintGradient.addColorStop(0.5, isDark ? '#111111' : '#FFB74D');
        paintGradient.addColorStop(1, currentPaint);
        ctx.fillStyle = paintGradient;
        ctx.beginPath();
        ctx.moveTo(15, 18);
        ctx.lineTo(29, 18);
        ctx.lineTo(28, 32);
        ctx.lineTo(16, 32);
        ctx.closePath();
        ctx.fill();

        // Drip
        const dripColor = isDark ? '#000000' : '#FF8A65';
        const dripGradient = ctx.createRadialGradient(22, 34, 0, 22, 34, 4);
        dripGradient.addColorStop(0, dripColor);
        dripGradient.addColorStop(1, isDark ? '#000' : '#E65100');
        ctx.fillStyle = dripGradient;
        ctx.beginPath();
        ctx.ellipse(22, 34, 3.5, 5, 0, 0, Math.PI * 2);
        ctx.fill();

        ctx.restore();

        // Spill (opposite mode)
        const spillColor = isDark ? '#FF9800' : '#000000';
        ctx.shadowBlur = 3;
        ctx.shadowColor = 'rgba(0,0,0,0.4)';
        drops.forEach(d => {
            const grad = ctx.createRadialGradient(d.x, d.y, 0, d.x, d.y, d.size * 2);
            grad.addColorStop(0, spillColor);
            grad.addColorStop(1, isDark ? '#E65100' : '#111');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.ellipse(d.x, d.y, d.size, d.size * 1.8, 0, 0, Math.PI * 2);
            ctx.fill();
        });

        splashes.forEach(s => {
            ctx.globalAlpha = s.alpha;
            ctx.fillStyle = spillColor;
            ctx.beginPath();
            ctx.moveTo(s.x, 38);
            for (let i = 0; i < 6; i++) {
                const a = (i * Math.PI * 2) / 6;
                const r = s.size * (0.6 + Math.random() * 0.4);
                ctx.lineTo(s.x + Math.cos(a) * r, 38 + Math.sin(a) * r * 0.5);
            }
            ctx.closePath();
            ctx.fill();
        });
        ctx.globalAlpha = 1;
        ctx.shadowBlur = 0;
    }

    function toppleAndSpill() {
        if (animating) return;
        animating = true;

        let frame = 0;
        const maxAngle = 92;
        const spillStart = 28;
        drops = [];
        splashes = [];

        function animate() {
            frame++;
            angle = Math.min(frame * 4.8, maxAngle);

            if (frame >= spillStart && frame % 2 === 0) {
                for (let i = 0; i < 5; i++) {
                    const offset = 15 + Math.random() * 10;
                    const spillX = 22 - offset * Math.cos((angle - 25) * Math.PI / 180);
                    const spillY = 38 - offset * Math.sin((angle - 25) * Math.PI / 180);
                    drops.push({
                        x: spillX,
                        y: spillY,
                        vx: -(2.5 + Math.random() * 3.5),
                        vy: -0.5 + Math.random() * 1.5,
                        size: 1.5 + Math.random() * 1.8,
                        life: 40
                    });
                }
            }

            drops = drops.filter(d => {
                d.x += d.vx;
                d.y += d.vy;
                d.vy += 0.45;
                d.vx *= 0.975;
                d.life--;
                if (d.y > 36 && d.life > 0) {
                    splashes.push({
                        x: d.x,
                        size: d.size * 2.5,
                        alpha: 0.6
                    });
                    d.life = 0;
                }
                return d.life > 0;
            });

            splashes = splashes.filter(s => {
                s.alpha -= 0.03;
                return s.alpha > 0;
            });

            drawBucket();

            if (frame < 60) {
                requestAnimationFrame(animate);
            } else {
                setTimeout(() => {
                    isDark = !isDark;
                    document.body.classList.toggle('dark', isDark);
                    localStorage.setItem('theme', isDark ? 'dark' : 'light');
                    angle = 0;
                    drops = [];
                    splashes = [];
                    animating = false;
                    drawBucket();
                }, 700);
            }
        }
        animate();
    }

    canvas.addEventListener('click', toppleAndSpill);

    // Load theme
    const saved = localStorage.getItem('theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        isDark = true;
        document.body.classList.add('dark');
    }
    drawBucket();
});