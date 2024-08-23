package com.nareun.easy_bank.controller;

import com.nareun.easy_bank.model.Notice;
import com.nareun.easy_bank.repository.NoticeRepsitory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
public class NoticesController {

    @Autowired
    private NoticeRepsitory noticeRepsitory;

    @GetMapping("/notices")
    public ResponseEntity<List<Notice>> getNotice() {
        List<Notice> notices = noticeRepsitory.findAllActiveNotices();
        if (notices != null) {
            return ResponseEntity.ok()
                    //* cacheControl : 캐시제어 -> 동일한 요청에 대해 서버가 반복적으로 처리하는 것을 방지
                    //* 이 응답이 60초동안 신선하다고 간주됨을 지정
                    //* HTTP헤더에 Cache-Control: max-age=60을 추가
                    /*
                 noCache(): 캐시는 가능하지만, 사용 전 서버의 재검증이 필요함을 나타냅니다.
                 noStore(): 응답을 절대 캐시하지 않도록 지시합니다.
                 private(): 개인 캐시에만 저장 가능함을 나타냅니다(공유 캐시에는 저장 불가).
                    */
                    .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                    .body(notices);
        } else {
            return null;
        }

    }
}
