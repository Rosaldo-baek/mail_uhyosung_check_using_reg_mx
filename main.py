import re
import os
from io import BytesIO

import pandas as pd
import dns.resolver
import streamlit as st


# 1. 이메일 문법 검사용 정규식 (1차 필터)
EMAIL_REGEX = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

# =========================
# [로컬파트(@ 앞) 길이 정책]
# =========================
# 디폴트 정책: "그 외 도메인은 5글자 이상" / 유저가 수정 가능
DEFAULT_MIN_LOCAL_LENGTH = 5  # <- 여기만 바꾸면 디폴트 최소 글자수 정책 변경 가능

# 도메인별 예외 정책
# - mode: "exact" (정확히 value글자), "min" (value글자 이상)
DOMAIN_LOCAL_LENGTH_RULES = {
    "naver.com": {"mode": "exact", "value": 5},  # @naver.com 이면 5글자(정확히)
    "daum.net": {"mode": "min", "value": 3},     # @daum.net 이면 3글자 이상
}


def check_syntax(email: str) -> bool:
    """
    간단한 정규식 기반 문법 체크.
    RFC 완전 구현 아님. 1차 필터 용도.
    """
    if not isinstance(email, str):
        return False
    email = email.strip()
    if not email:
        return False
    return EMAIL_REGEX.match(email) is not None


def get_local_length_rule(domain: str) -> dict:
    """
    도메인별 로컬파트 길이 규칙 조회 함수임
    - 매칭되는 도메인이 있으면 해당 규칙 반환
    - 없으면 디폴트(min, DEFAULT_MIN_LOCAL_LENGTH) 반환
    """
    domain = (domain or "").strip().lower()
    if domain in DOMAIN_LOCAL_LENGTH_RULES:
        return DOMAIN_LOCAL_LENGTH_RULES[domain]
    return {"mode": "min", "value": DEFAULT_MIN_LOCAL_LENGTH}


def check_mx_or_a(domain: str, timeout: float = 3.0) -> (bool, str):
    """
    도메인에 대해 MX 레코드 → 없으면 A 레코드까지 확인.
    반환: (has_mail_server, detail_ko)
      - has_mail_server: 메일 수신 가능성이 있는지 여부
      - detail_ko: 한국어 설명 문자열
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    # 1순위: MX 레코드
    try:
        answers = resolver.resolve(domain, 'MX')
        if len(answers) > 0:
            return True, "MX 레코드가 존재합니다."
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        # MX 없음 또는 도메인 없음 → A 레코드 확인으로 진행
        pass
    except Exception as e:
        return False, f"MX 레코드 조회 중 오류가 발생했습니다: {e}"

    # MX가 없을 때 A 레코드 확인 (일부 서버는 A만으로 메일 수신)
    try:
        answers_a = resolver.resolve(domain, 'A')
        if len(answers_a) > 0:
            return True, "MX 레코드는 없고 A 레코드만 존재합니다."
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False, "해당 도메인에 MX/A 레코드가 없습니다."
    except Exception as e:
        return False, f"A 레코드 조회 중 오류가 발생했습니다: {e}"

    return False, "해당 도메인에 MX/A 레코드가 없습니다."


def validate_email_basic(email: str) -> dict:
    """
    정규식 + DNS(MX/A) 기반 기본 유효성 검증.
    1) 전체 결과 한국어
    2) 도메인별 로컬파트(@ 앞) 길이 조건 적용
       - naver.com: exact 5
       - daum.net: min 3
       - others: min DEFAULT_MIN_LOCAL_LENGTH (기본 5, 유저 수정 가능)
    """
    result = {
        "original_email": email,
        "is_valid": False,          # 최종 판단
        "status": "검사 안 됨",       # 정상 / 문자열 아님 / 빈 값 / 문법 오류 / 아이디 길이 부족 / 도메인 오류 / DNS 오류
        "error": None,              # 한글 설명
        "domain": None,
        "has_mail_server": None,    # True / False / None(도메인 추출 실패 등)
        "detail": None,             # MX/A 조회 상세 설명(한국어)
        "local_length": None,       # @ 앞 글자수
    }

    # 1) 타입/공백 체크
    if not isinstance(email, str):
        result["status"] = "문자열 아님"
        result["error"] = "문자열이 아닌 값입니다."
        return result

    email_stripped = email.strip()
    if not email_stripped:
        result["status"] = "빈 값"
        result["error"] = "공백이거나 빈 문자열입니다."
        return result

    # 2) 정규식 문법 검사
    if not check_syntax(email_stripped):
        result["status"] = "문법 오류"
        result["error"] = "이메일 형식이 올바르지 않습니다."
        return result

    # 3) 로컬/도메인 분리
    try:
        local, domain = email_stripped.rsplit("@", 1)
    except ValueError:
        result["status"] = "문법 오류"
        result["error"] = "이메일에서 아이디와 도메인을 분리할 수 없습니다."
        return result

    local = local.strip()
    domain = domain.strip().lower()
    result["domain"] = domain
    result["local_length"] = len(local)

    # 4) 아이디(로컬파트) 길이 검사: 도메인별 규칙 적용
    rule = get_local_length_rule(domain)
    mode = rule.get("mode")
    value = int(rule.get("value", DEFAULT_MIN_LOCAL_LENGTH))

    # - exact: 길이가 value와 정확히 같아야 함
    if mode == "exact":
        if len(local) != value:
            result["status"] = "아이디 길이 부족"
            result["error"] = f"{domain} 도메인은 아이디 글자수가 정확히 {value}자여야 합니다."
            result["detail"] = f"아이디 글자수가 {len(local)}자입니다. (정확히 {value}자 필요)"
            return result

    # - min: 길이가 value 이상이어야 함
    else:
        # 기존 코드의 <= 비교는 정책에 따라 오류 유발 가능해서 < 로 수정함
        if len(local) < value:
            result["status"] = "아이디 길이 부족"
            result["error"] = f"최소 아이디 글자수({value}) 미달입니다."
            result["detail"] = f"아이디 글자수가 {len(local)}자입니다. ({value}자 이상 필요)"
            return result

    # 5) MX/A 레코드 조회
    try:
        has_mail_server, detail = check_mx_or_a(domain)
    except Exception as e:
        # dnspython 자체 예외 등
        result["status"] = "DNS 오류"
        result["error"] = "도메인 또는 메일 서버 정보를 조회하는 중 오류가 발생했습니다."
        result["detail"] = str(e)
        return result

    result["has_mail_server"] = has_mail_server
    result["detail"] = detail

    if not has_mail_server:
        # 도메인 자체가 메일 수신 설정이 안 되어 있을 가능성이 큼
        result["status"] = "도메인 오류"
        result["error"] = "해당 도메인에 메일 서버(MX/A)가 없습니다."
        return result

    # 여기까지 통과하면 기본 유효
    result["is_valid"] = True
    result["status"] = "정상"
    result["error"] = None
    return result


def run_app():
    st.title("이메일 유효성 검증 도구 (정규식 + DNS)")

    st.write("- 업로드 엑셀에 `mail` 컬럼 필수임")
    st.write("- 결과 파일명: 원본파일명 + `_email_valid_check_com`")
    st.write(f"- 디폴트 로컬파트 최소 글자수: {DEFAULT_MIN_LOCAL_LENGTH}자 (코드 상단에서 변경 가능)")

    uploaded_file = st.file_uploader(
        "엑셀 파일 업로드 (mail 컬럼 필수)",
        type=["xlsx", "xls"]
    )

    if uploaded_file is None:
        return

    # 엑셀 읽기
    try:
        df = pd.read_excel(uploaded_file)
    except Exception as e:
        st.error(f"엑셀 파일을 읽는 중 오류가 발생했습니다: {e}")
        return

    # mail 컬럼 확인
    if "mail" not in df.columns:
        st.error("엑셀에 'mail' 컬럼이 없습니다. 컬럼명을 정확히 'mail' 로 맞춰주세요.")
        st.dataframe(df.head())
        return

    st.success("'mail' 컬럼 확인됨")
    st.write("데이터 미리보기 (상위 5행):")
    st.dataframe(df.head())

    if st.button("이메일 유효성 검증 실행"):
        with st.spinner("검증 중... DNS 조회 포함으로 시간이 다소 소요될 수 있음"):
            mail_series = df["mail"]

            results = []
            for row_idx, email in mail_series.items():
                info = validate_email_basic(email)
                info["row_index"] = row_idx
                results.append(info)

            result_df = pd.DataFrame(results)

            # 원본 df에 결과 join
            merged_df = df.join(result_df, how="left")

        # 요약 정보 표시
        valid_count = int(merged_df["is_valid"].sum(skipna=True))
        total_count = len(merged_df)

        st.subheader("검증 요약")
        st.write(f"- 전체 행 수: {total_count}")
        st.write(f"- 유효 이메일 개수: {valid_count}")
        st.write(f"- 무효 이메일 개수: {total_count - valid_count}")

        st.subheader("무효 이메일 상위 10개")
        invalid_sample = (
            merged_df[merged_df["is_valid"] == False]
            [["mail", "status", "error", "domain", "local_length", "detail"]]
            .head(10)
        )
        if len(invalid_sample) == 0:
            st.write("무효 이메일 없음")
        else:
            st.dataframe(invalid_sample)

        # 다운로드용 엑셀 생성
        base_name, ext = os.path.splitext(uploaded_file.name)
        if ext == "":
            ext = ".xlsx"
        output_name = f"{base_name}_email_valid_check_com{ext}"

        buffer = BytesIO()
        merged_df.to_excel(buffer, index=False)
        buffer.seek(0)

        st.subheader("결과 파일 다운로드")
        st.download_button(
            label="검증 결과 엑셀 다운로드",
            data=buffer,
            file_name=output_name,
            mime=(
                "application/vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet"
            ),
        )


if __name__ == "__main__":
    run_app()

