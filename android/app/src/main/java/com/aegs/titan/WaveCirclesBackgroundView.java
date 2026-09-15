package com.aegs.titan;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * AEGS Titan - Native Canvas Background with clean semi-transparent circles.
 * During connection, circles align horizontally at button level and undulate in a traveling wave.
 */
public class WaveCirclesBackgroundView extends View {

    public static final int STATE_RANDOM = 0;
    public static final int STATE_WAVE = 1;
    public static final int STATE_CONNECTED = 2;

    private int mState = STATE_RANDOM;
    private long mWaveStartTime = 0;
    private float mButtonLevelY = -1;

    private static final int NUM_CIRCLES = 15;
    private final List<CircleItem> mCircles = new ArrayList<>();
    private final Paint mFillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint mStrokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private static class CircleItem {
        float x, y;
        float vx, vy;
        float r, baseR;
        int colorIndex;
    }

    public WaveCirclesBackgroundView(Context context) {
        super(context);
        init();
    }

    public WaveCirclesBackgroundView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public WaveCirclesBackgroundView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        mFillPaint.setStyle(Paint.Style.FILL);
        mStrokePaint.setStyle(Paint.Style.STROKE);
        mStrokePaint.setStrokeWidth(3f);
    }

    @Override
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        initCircles(w, h);
    }

    private void initCircles(int w, int h) {
        mCircles.clear();
        Random rnd = new Random();
        float density = getResources().getDisplayMetrics().density;
        for (int i = 0; i < NUM_CIRCLES; i++) {
            CircleItem c = new CircleItem();
            float r = (16f + rnd.nextFloat() * 30f) * density;
            c.r = r;
            c.baseR = r;
            c.x = r + rnd.nextFloat() * (Math.max(w - 2 * r, 10));
            c.y = r + rnd.nextFloat() * (Math.max(h - 2 * r, 10));
            c.vx = (rnd.nextFloat() - 0.5f) * 1.6f * density;
            c.vy = (rnd.nextFloat() - 0.5f) * 1.6f * density;
            c.colorIndex = i % 4;
            mCircles.add(c);
        }
    }

    public void setState(int state, float buttonCenterY) {
        mState = state;
        mButtonLevelY = buttonCenterY;
        if (state == STATE_WAVE) {
            mWaveStartTime = System.currentTimeMillis();
        }
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();
        if (w == 0 || h == 0 || mCircles.isEmpty()) return;

        float density = getResources().getDisplayMetrics().density;
        float btnY = (mButtonLevelY > 0) ? mButtonLevelY : h * 0.28f;
        float spacing = (w - 70f * density) / (NUM_CIRCLES - 1);
        float startX = 35f * density;
        long now = System.currentTimeMillis();

        for (int i = 0; i < mCircles.size(); i++) {
            CircleItem c = mCircles.get(i);

            if (mState == STATE_RANDOM) {
                c.x += c.vx;
                c.y += c.vy;
                if (c.x < c.r || c.x > w - c.r) c.vx *= -1;
                if (c.y < c.r || c.y > h - c.r) c.vy *= -1;
                c.r += (c.baseR - c.r) * 0.05f;

            } else if (mState == STATE_WAVE) {
                float targetX = startX + i * spacing;
                float elapsed = (now - mWaveStartTime) / 1000f;
                float waveOffset = (float) Math.sin(elapsed * 4.4f + (i * 0.58f)) * 36f * density;
                float targetY = btnY + waveOffset;

                c.x += (targetX - c.x) * 0.09f;
                c.y += (targetY - c.y) * 0.09f;

                float targetR = c.baseR * 0.72f + (float) Math.sin(elapsed * 3.5f + i * 0.5f) * 4f * density;
                c.r += (targetR - c.r) * 0.08f;

            } else if (mState == STATE_CONNECTED) {
                float targetX = startX + i * spacing;
                float elapsed = now / 1000f;
                float targetY = btnY + (float) Math.sin(elapsed * 1.6f + i * 0.35f) * 8f * density;
                c.x += (targetX - c.x) * 0.05f;
                c.y += (targetY - c.y) * 0.05f;
            }

            // Warm Amber semi-transparent palette
            int fill;
            int stroke;
            if (c.colorIndex == 0) {
                fill = 0x38F59E0B;   // Amber primary semi-trans
                stroke = 0x66F59E0B;
            } else if (c.colorIndex == 1) {
                fill = 0x2AFB923C;   // Amber light semi-trans
                stroke = 0x55FB923C;
            } else if (c.colorIndex == 2) {
                fill = 0x22D97706;   // Honey amber semi-trans
                stroke = 0x4CD97706;
            } else {
                fill = 0x14FFFFFF;   // Subtle frost
                stroke = 0x30FFFFFF;
            }

            mFillPaint.setColor(fill);
            mStrokePaint.setColor(stroke);

            canvas.drawCircle(c.x, c.y, c.r, mFillPaint);
            canvas.drawCircle(c.x, c.y, c.r, mStrokePaint);
        }

        postInvalidateOnAnimation();
    }
}
