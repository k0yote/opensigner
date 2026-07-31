'use client';

import { useEffect, useState } from 'react';

type SVGSequenceProps = {
    /** Frame URLs, rendered in order and cycled. */
    svgUrls: readonly string[];
    /** Any CSS width value. */
    imgSize?: string;
    /** Milliseconds per frame. */
    interval?: number;
};

export function SVGSequence({ imgSize = '100%', svgUrls, interval = 2000 }: SVGSequenceProps) {
    const [current, setCurrent] = useState(0);

    useEffect(() => {
        // A zero-length sequence would make the modulo below divide by zero and
        // leave the index NaN, so there is nothing to animate.
        if (svgUrls.length === 0) return;

        const timer = setInterval(() => {
            setCurrent(prev => (prev + 1) % svgUrls.length);
        }, interval);

        return () => clearInterval(timer);
    }, [svgUrls, interval]);

    return (
        <div className="svg-animation-container" style={{ position: 'relative', width: '100%', backgroundColor: 'transparent' }}>
            {svgUrls.map((url: string, index: number) => (
                <img
                    key={url}
                    src={url}
                    alt={`SVG frame ${index}`}
                    style={{
                        position: index === current ? 'relative' : 'absolute',
                        top: 0,
                        left: 0,
                        width: imgSize,
                        height: 'auto',
                        margin: 'auto',
                        opacity: index === current ? 1 : 0,
                        pointerEvents: index === current ? 'auto' : 'none',
                        transition: 'linear',
                        backgroundColor: 'transparent',
                    }}
                />
            ))}
        </div>
    );
}
