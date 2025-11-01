// static/js/graffiti.js
document.addEventListener('DOMContentLoaded', () => {
    const toggles = document.querySelectorAll('.password-toggle');
    toggles.forEach(btn => {
        const input = btn.previousElementSibling;
        if (!input || input.type !== 'password') return;

        const canvas = document.createElement('canvas');
        canvas.width = 36; canvas.height = 36;
        canvas.style.cursor = 'pointer';
        canvas.style.marginLeft = '8px';
        canvas.title = 'Show/Hide Password';

        btn.parentNode.style.display = 'inline-flex';
        btn.parentNode.style.alignItems = 'center';
        btn.parentNode.insertBefore(canvas, btn);
        btn.style.display = 'none';

        const ctx = canvas.getContext('2d');
        let revealed = false;
        let spraying = false;
        let sprayParticles = [];

        function drawCan() {
            ctx.clearRect(0, 0, 36, 36);

            // Can body (metallic)
            ctx.fillStyle = '#455A64';
            ctx.beginPath();
            ctx.roundRect(10, 8, 16, 24, 4);
            ctx.fill();

            // Can top (nozzle on RIGHT side)
            ctx.fillStyle = '#78909C';
            ctx.beginPath();
            ctx.roundRect(20, 6, 8, 6, 2);
            ctx.fill();

            // Nozzle hole (on right)
            ctx.fillStyle = '#263238';
            ctx.beginPath();
            ctx.ellipse(26, 9, 2, 2, 0, 0, Math.PI * 2);
            ctx.fill();

            // Label band
            ctx.fillStyle = '#E65100';
            ctx.beginPath();
            ctx.roundRect(11, 16, 14, 6, 1);
            ctx.fill();

            // "SPRAY" text
            ctx.fillStyle = '#FFF';
            ctx.font = 'bold 5px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('SPRAY', 18, 20);

            // Spray cloud (when active)
            if (spraying || revealed) {
                ctx.globalAlpha = 0.7;
                ctx.fillStyle = '#FF9800';
                sprayParticles.forEach(p => {
                    ctx.beginPath();
                    ctx.ellipse(p.x, p.y, p.size, p.size, 0, 0, Math.PI * 2);
                    ctx.fill();
                });
                ctx.globalAlpha = 1;
            }
        }

        function startSpray() {
            if (spraying) return;
            spraying = true;
            revealed = true;
            input.type = 'text';

            let frame = 0;
            sprayParticles = [];

            function animate() {
                frame++;

                // Generate spray particles from RIGHT nozzle to LEFT
                if (frame % 2 === 0 && frame < 40) {
                    for (let i = 0; i < 8; i++) {
                        const angle = (Math.random() * 60 + 120) * Math.PI / 180; // 120° to 180° = left cone
                        const speed = 2 + Math.random() * 4;
                        sprayParticles.push({
                            x: 26 + Math.cos(angle) * 6,  // start from nozzle
                            y: 9 + Math.sin(angle) * 6,
                            vx: Math.cos(angle) * speed,
                            vy: Math.sin(angle) * speed + 1,
                            size: 1 + Math.random() * 2,
                            life: 30 + Math.random() * 20
                        });
                    }
                }

                // Update particles
                sprayParticles = sprayParticles.filter(p => {
                    p.x += p.vx;
                    p.y += p.vy;
                    p.vy += 0.3;
                    p.life--;
                    p.size *= 0.98;
                    return p.life > 0 && p.y < 50 && p.x > -20;
                });

                drawCan();

                if (frame < 60) {
                    requestAnimationFrame(animate);
                } else {
                    setTimeout(() => {
                        spraying = false;
                        if (!revealed) drawCan();
                    }, 300);
                }
            }
            animate();
        }

        function resetCan() {
            revealed = false;
            input.type = 'password';
            sprayParticles = [];
            drawCan();
        }

        canvas.addEventListener('click', () => {
            if (spraying) return;
            if (revealed) {
                resetCan();
            } else {
                startSpray();
            }
        });

        drawCan();
    });
});