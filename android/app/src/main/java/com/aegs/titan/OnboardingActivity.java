package com.aegs.titan;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class OnboardingActivity extends AppCompatActivity {

    private AnimShieldSpeedometerView mAnimView;
    private View mSourceSelector;
    private TextView mTvTitle;
    private TextView mTvDesc;
    private View[] mDots;
    private Button mBtnNext;
    private View mBtnSkip;

    private int mCurrentStep = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        mAnimView = findViewById(R.id.anim_view);
        mSourceSelector = findViewById(R.id.ll_source_selector);
        mTvTitle = findViewById(R.id.tv_onboarding_title);
        mTvDesc = findViewById(R.id.tv_onboarding_desc);
        mBtnNext = findViewById(R.id.btn_next);
        mBtnSkip = findViewById(R.id.btn_skip);

        mDots = new View[]{
            findViewById(R.id.dot_0),
            findViewById(R.id.dot_1),
            findViewById(R.id.dot_2),
            findViewById(R.id.dot_3)
        };

        mBtnNext.setOnClickListener(v -> nextStep());
        if (mBtnSkip != null) {
            mBtnSkip.setOnClickListener(v -> finishOnboarding());
        }

        findViewById(R.id.card_source_cloud).setOnClickListener(v -> selectSource("cloud"));
        findViewById(R.id.card_source_qr).setOnClickListener(v -> selectSource("qr"));
        findViewById(R.id.card_source_vps).setOnClickListener(v -> selectSource("vps"));

        updateUI();
    }

    private void selectSource(String type) {
        SharedPreferences prefs = getSharedPreferences("aegs_prefs", MODE_PRIVATE);
        if ("vps".equals(type)) {
            prefs.edit().putString("source_mode", "vps").apply();
        } else if ("qr".equals(type)) {
            prefs.edit().putString("source_mode", "qr").apply();
        } else {
            prefs.edit().putString("source_mode", "cloud").apply();
        }
        finishOnboarding();
    }

    private void nextStep() {
        if (mCurrentStep < 3) {
            mCurrentStep++;
            updateUI();
        } else {
            finishOnboarding();
        }
    }

    private void updateUI() {
        for (int i = 0; i < mDots.length; i++) {
            if (i == mCurrentStep) {
                mDots[i].setBackgroundColor(0xFFF59E0B);
                mDots[i].getLayoutParams().width = (int) (24 * getResources().getDisplayMetrics().density);
            } else {
                mDots[i].setBackgroundColor(0x33FFFFFF);
                mDots[i].getLayoutParams().width = (int) (8 * getResources().getDisplayMetrics().density);
            }
            mDots[i].requestLayout();
        }

        if (mCurrentStep == 0) {
            mAnimView.setVisibility(View.VISIBLE);
            mSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_WELCOME);
            mTvTitle.setText("Добро пожаловать в AEGS");
            mTvDesc.setText("Свободный и безопасный интернет без цензуры, слежки и замедлений провайдера.");
            mBtnNext.setText("ДАЛЕЕ ➔");
        } else if (mCurrentStep == 1) {
            mAnimView.setVisibility(View.VISIBLE);
            mSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_LOCK);
            mTvTitle.setText("Абсолютная безопасность");
            mTvDesc.setText("Шифрование ChaCha20-Poly1305 и маскировка RFC 9000 QUIC. Трафик неотличим от обычного веб-сайта.");
            mBtnNext.setText("ДАЛЕЕ ➔");
        } else if (mCurrentStep == 2) {
            mAnimView.setVisibility(View.VISIBLE);
            mSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_SPEEDOMETER);
            mTvTitle.setText("Скорость до 900+ Мбит/с");
            mTvDesc.setText("Аппаратное zero-copy ядро. Мгновенная загрузка 4K-видео на YouTube и минимальный пинг в Discord.");
            mBtnNext.setText("ДАЛЕЕ ➔");
        } else if (mCurrentStep == 3) {
            mAnimView.setVisibility(View.GONE);
            mSourceSelector.setVisibility(View.VISIBLE);
            mTvTitle.setText("Выберите способ подключения");
            mTvDesc.setText("Используйте подписку по ссылке, сканируйте QR-код или подключите свой личный сервер.");
            mBtnNext.setText("ЗАПУСТИТЬ AEGS 🚀");
        }
    }

    private void finishOnboarding() {
        SharedPreferences prefs = getSharedPreferences("aegs_prefs", MODE_PRIVATE);
        prefs.edit().putBoolean("onboarding_done", true).apply();
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }
}
