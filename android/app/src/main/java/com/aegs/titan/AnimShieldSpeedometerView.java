package com.aegs.titan;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import androidx.annotation.Nullable;

public class AnimShieldSpeedometerView extends View {

    public static final int MODE_WELCOME = 0;
    public static final int MODE_LOCK = 1;
    public static final int MODE_SPEEDOMETER = 2;

    private int mCurrentMode = MODE_WELCOME;

    private Paint mPaintBody;
    private Paint mPaintShackle;
    private Paint mPaintGlow;
    private Paint mPaintGauge;
    private Paint mPaintNeedle;
    private Paint mPaintText;
    private Paint mPaintSubText;

    private float mPulseProgress = 0f;
    private float mShackleOffset = 0f;
    private float mLockGlowAlpha = 0f;
    private float mNeedleAngle = 0f;
    private float mSpeedDisplayVal = 0f;

    private ValueAnimator mPulseAnim;
    private ValueAnimator mLockAnim;
    private ValueAnimator mSpeedAnim;

    public AnimShieldSpeedometerView(Context context) {
        super(context);
        init();
    }

    public AnimShieldSpeedometerView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public AnimShieldSpeedometerView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        float density = getResources().getDisplayMetrics().density;

        mPaintBody = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintBody.setColor(0xFF1C1917);
        mPaintBody.setStyle(Paint.Style.FILL);

        mPaintShackle = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintShackle.setColor(0xFFD4D4D8);
        mPaintShackle.setStyle(Paint.Style.STROKE);
        mPaintShackle.setStrokeWidth(14f * density);
        mPaintShackle.setStrokeCap(Paint.Cap.ROUND);

        mPaintGlow = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintGlow.setColor(0xFFF59E0B);
        mPaintGlow.setStyle(Paint.Style.STROKE);
        mPaintGlow.setStrokeWidth(3.5f * density);

        mPaintGauge = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintGauge.setStyle(Paint.Style.STROKE);
        mPaintGauge.setStrokeCap(Paint.Cap.ROUND);

        mPaintNeedle = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintNeedle.setColor(0xFFF59E0B);
        mPaintNeedle.setStyle(Paint.Style.STROKE);
        mPaintNeedle.setStrokeWidth(6f * density);
        mPaintNeedle.setStrokeCap(Paint.Cap.ROUND);

        mPaintText = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintText.setColor(0xFFFFFFFF);
        mPaintText.setTextAlign(Paint.Align.CENTER);
        mPaintText.setTextSize(26f * density);
        mPaintText.setFakeBoldText(true);

        mPaintSubText = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintSubText.setColor(0xFFF59E0B);
        mPaintSubText.setTextAlign(Paint.Align.CENTER);
        mPaintSubText.setTextSize(13f * density);
        mPaintSubText.setFakeBoldText(true);

        startPulseAnimation();
    }

    public void setMode(int mode) {
        mCurrentMode = mode;
        if (mode == MODE_WELCOME) {
            startPulseAnimation();
        } else if (mode == MODE_LOCK) {
            startLockAnimation();
        } else if (mode == MODE_SPEEDOMETER) {
            startSpeedometerAnimation();
        }
        invalidate();
    }

    private void startPulseAnimation() {
        if (mPulseAnim != null) mPulseAnim.cancel();
        mPulseAnim = ValueAnimator.ofFloat(0f, 1f);
        mPulseAnim.setDuration(1600);
        mPulseAnim.setRepeatMode(ValueAnimator.REVERSE);
        mPulseAnim.setRepeatCount(ValueAnimator.INFINITE);
        mPulseAnim.addUpdateListener(anim -> {
            mPulseProgress = (float) anim.getAnimatedValue();
            invalidate();
        });
        mPulseAnim.start();
    }

    public void startLockAnimation() {
        if (mLockAnim != null) mLockAnim.cancel();
        mShackleOffset = 0f;
        mLockGlowAlpha = 0f;

        mLockAnim = ValueAnimator.ofFloat(0f, 1f);
        mLockAnim.setDuration(800);
        mLockAnim.setInterpolator(new OvershootInterpolator(1.4f));
        mLockAnim.addUpdateListener(anim -> {
            mShackleOffset = (float) anim.getAnimatedValue();
            if (mShackleOffset > 0.8f) {
                mLockGlowAlpha = (mShackleOffset - 0.8f) * 5f;
            }
            invalidate();
        });
        mLockAnim.start();
    }

    public void startSpeedometerAnimation() {
        if (mSpeedAnim != null) mSpeedAnim.cancel();
        mNeedleAngle = 0f;
        mSpeedDisplayVal = 0f;

        mSpeedAnim = ValueAnimator.ofFloat(0f, 1.0f);
        mSpeedAnim.setDuration(1400);
        mSpeedAnim.setInterpolator(new AccelerateDecelerateInterpolator());
        mSpeedAnim.addUpdateListener(anim -> {
            float frac = (float) anim.getAnimatedValue();
            mNeedleAngle = frac;
            mSpeedDisplayVal = frac * 940f;
            invalidate();
        });
        mSpeedAnim.start();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float cx = getWidth() / 2f;
        float cy = getHeight() / 2f;
        if (cx <= 0 || cy <= 0) return;

        float density = getResources().getDisplayMetrics().density;

        if (mCurrentMode == MODE_WELCOME) {
            drawWelcome(canvas, cx, cy, density);
        } else if (mCurrentMode == MODE_LOCK) {
            drawLock(canvas, cx, cy, density);
        } else if (mCurrentMode == MODE_SPEEDOMETER) {
            drawSpeedometer(canvas, cx, cy, density);
        }
    }

    private void drawWelcome(Canvas canvas, float cx, float cy, float density) {
        float r = 70f * density;
        mPaintGlow.setColor(0xFFF59E0B);
        mPaintGlow.setAlpha((int) (60 + mPulseProgress * 80));
        canvas.drawCircle(cx, cy, r + mPulseProgress * 10f * density, mPaintGlow);

        Path shield = new Path();
        shield.moveTo(cx, cy - 50f * density);
        shield.quadTo(cx + 50f * density, cy - 50f * density, cx + 50f * density, cy);
        shield.quadTo(cx + 50f * density, cy + 45f * density, cx, cy + 65f * density);
        shield.quadTo(cx - 50f * density, cy + 45f * density, cx - 50f * density, cy);
        shield.quadTo(cx - 50f * density, cy - 50f * density, cx, cy - 50f * density);
        shield.close();

        mPaintBody.setColor(0xFF17161C);
        canvas.drawPath(shield, mPaintBody);
        mPaintGlow.setAlpha(255);
        canvas.drawPath(shield, mPaintGlow);

        canvas.drawText("AEGS", cx, cy - 5f * density, mPaintText);
        canvas.drawText("TITAN v6.2", cx, cy + 22f * density, mPaintSubText);
    }

    private void drawLock(Canvas canvas, float cx, float cy, float density) {
        float drop = 35f * density * mShackleOffset;

        RectF shackleArc = new RectF(cx - 32f * density, cy - 55f * density + drop, cx + 32f * density, cy + 9f * density + drop);
        canvas.drawArc(shackleArc, 180, 180, false, mPaintShackle);
        canvas.drawLine(cx - 32f * density, cy - 23f * density + drop, cx - 32f * density, cy + 20f * density, mPaintShackle);
        canvas.drawLine(cx + 32f * density, cy - 23f * density + drop, cx + 32f * density, cy + 20f * density, mPaintShackle);

        RectF bodyRect = new RectF(cx - 50f * density, cy - 4f * density, cx + 50f * density, cy + 70f * density);
        mPaintBody.setColor(0xFF1C1917);
        canvas.drawRoundRect(bodyRect, 16f * density, 16f * density, mPaintBody);
        mPaintGlow.setColor(0xFFF59E0B);
        mPaintGlow.setAlpha(255);
        canvas.drawRoundRect(bodyRect, 16f * density, 16f * density, mPaintGlow);

        mPaintBody.setColor(0xFFF59E0B);
        canvas.drawCircle(cx, cy + 24f * density, 8f * density, mPaintBody);
        canvas.drawRect(cx - 4f * density, cy + 24f * density, cx + 4f * density, cy + 48f * density, mPaintBody);

        if (mLockGlowAlpha > 0f) {
            Paint burst = new Paint(Paint.ANTI_ALIAS_FLAG);
            burst.setStyle(Paint.Style.STROKE);
            burst.setColor(0xFFF59E0B);
            burst.setStrokeWidth(4f * density);
            burst.setAlpha((int) (mLockGlowAlpha * 180));
            canvas.drawCircle(cx, cy + 30f * density, 75f * density * mLockGlowAlpha, burst);
        }
    }

    private void drawSpeedometer(Canvas canvas, float cx, float cy, float density) {
        float r = 85f * density;
        RectF arcRect = new RectF(cx - r, cy - r, cx + r, cy + r);

        mPaintGauge.setColor(0x33FFFFFF);
        mPaintGauge.setStrokeWidth(12f * density);
        canvas.drawArc(arcRect, 135, 270, false, mPaintGauge);

        mPaintGauge.setColor(0xFFF59E0B);
        canvas.drawArc(arcRect, 135, 270 * mNeedleAngle, false, mPaintGauge);

        float sweepRad = (float) Math.toRadians(135 + 270 * mNeedleAngle);
        float nx = cx + (float) Math.cos(sweepRad) * (r - 10f * density);
        float ny = cy + (float) Math.sin(sweepRad) * (r - 10f * density);
        canvas.drawLine(cx, cy, nx, ny, mPaintNeedle);

        mPaintBody.setColor(0xFFF59E0B);
        canvas.drawCircle(cx, cy, 10f * density, mPaintBody);

        canvas.drawText(String.valueOf(Math.round(mSpeedDisplayVal)), cx, cy + 42f * density, mPaintText);
        canvas.drawText("Мбит/с (LTO Turbo)", cx, cy + 62f * density, mPaintSubText);
    }
}
