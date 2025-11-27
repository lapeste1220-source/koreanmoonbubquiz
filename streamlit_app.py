# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
import hashlib
import datetime
from pathlib import Path
import random

# ---------------- 기본 설정 ----------------
st.set_page_config(
    page_title="함창고 국어 문법 문제은행",
    layout="wide"
)

st.title("함창고 국어 문법 문제은행")
st.caption("로그인 후 퀴즈에 도전하고, 국어 문법 실력을 진단해 보세요!")

TODAY_STR = datetime.date.today().isoformat()

# 파일 경로 설정
QUESTIONS_FILE = Path("questions.csv")
USERS_FILE = Path("users.csv")
QUIZ_LOG_FILE = Path("quiz_log.csv")
QUIZ_SESSIONS_FILE = Path("quiz_sessions.csv")

# 관리자 비밀번호 (관리자 메뉴 접속용)
ADMIN_MENU_PASSWORD = "grammarAdmin123"

# 난도별 점수
DIFFICULTY_SCORE = {
    "상": 3,
    "중": 2,
    "하": 1
}

# 영역 가중치 (출제 비중)
HIGH_FREQ_AREAS = ["음운", "단어", "문장", "문법요소", "중세국어"]


# ---------------- 유틸 함수: 파일 로딩/저장 ----------------
@st.cache_data
def load_questions():
    if not QUESTIONS_FILE.exists():
        st.error("문제 파일 questions.csv 를 찾을 수 없습니다. 리포지토리에 업로드해 주세요.")
        return pd.DataFrame()
    df = pd.read_csv(QUESTIONS_FILE)

    # CSV 실제 헤더를 표준 이름으로 맞추기
    rename_map = {
        "난이도": "난도",
        "보기1": "선지1",
        "보기2": "선지2",
        "보기3": "선지3",
        "보기4": "선지4",
    }
    df = df.rename(columns=rename_map)

    required_cols = ["문항ID", "영역", "난도", "문제",
                     "선지1", "선지2", "선지3", "선지4", "정답", "해설"]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        st.error(f"questions.csv 에 다음 컬럼이 필요합니다: {missing}")
        st.write("현재 CSV 컬럼 목록:", [str(c) for c in df.columns.tolist()])
        return pd.DataFrame()

    return df


def load_users():
    if USERS_FILE.exists():
        return pd.read_csv(USERS_FILE, dtype={"username": str, "student_id": str})
    else:
        return pd.DataFrame(columns=["username", "password_hash", "student_id", "name", "email", "is_admin"])


def save_users(df_users):
    df_users.to_csv(USERS_FILE, index=False, encoding="utf-8-sig")


def load_quiz_log():
    if QUIZ_LOG_FILE.exists():
        return pd.read_csv(QUIZ_LOG_FILE)
    else:
        return pd.DataFrame(columns=[
            "username", "session_id", "문항ID", "정답여부",
            "난도", "영역", "득점", "풀이시간초", "응시일"
        ])


def save_quiz_log(df_log):
    df_log.to_csv(QUIZ_LOG_FILE, index=False, encoding="utf-8-sig")


def load_quiz_sessions():
    if QUIZ_SESSIONS_FILE.exists():
        return pd.read_csv(QUIZ_SESSIONS_FILE)
    else:
        return pd.DataFrame(columns=[
            "username", "session_id",
            "총점", "총문항수", "정답수",
            "정답률", "총풀이시간초", "시작시각", "종료시각"
        ])


def save_quiz_sessions(df_sessions):
    df_sessions.to_csv(QUIZ_SESSIONS_FILE, index=False, encoding="utf-8-sig")


# ---------------- 유틸: 비밀번호 해시 ----------------
SALT = "hamchang-grammar-salt"


def hash_password(password: str) -> str:
    return hashlib.sha256((password + SALT).encode("utf-8")).hexdigest()


# ---------------- 회원 관리 ----------------
def register_user(username, password, student_id, name, email):
    df_users = load_users()
    if username in df_users["username"].values:
        return False, "이미 사용 중인 아이디입니다."
    if student_id in df_users["student_id"].astype(str).values:
        return False, "이미 등록된 학번입니다."

    new_row = {
        "username": username,
        "password_hash": hash_password(password),
        "student_id": str(student_id),
        "name": name,
        "email": email,
        "is_admin": False
    }
    df_users = pd.concat([df_users, pd.DataFrame([new_row])], ignore_index=True)
    save_users(df_users)
    return True, "회원가입이 완료되었습니다. 이제 로그인해 주세요."


def authenticate_user(username, password):
    df_users = load_users()
    row = df_users[df_users["username"] == username]
    if row.empty:
        return None
    stored_hash = row.iloc[0]["password_hash"]
    if stored_hash == hash_password(password):
        return row.iloc[0]
    return None


def change_user_password(target_username, new_password):
    df_users = load_users()
    idx = df_users.index[df_users["username"] == target_username]
    if len(idx) == 0:
        return False, "해당 아이디를 찾을 수 없습니다."
    df_users.loc[idx, "password_hash"] = hash_password(new_password)
    save_users(df_users)
    return True, "비밀번호가 변경되었습니다."


def delete_user(target_username):
    df_users = load_users()
    if target_username not in df_users["username"].values:
        return False, "해당 아이디를 찾을 수 없습니다."
    df_users = df_users[df_users["username"] != target_username]
    save_users(df_users)
    return True, "해당 회원 정보가 삭제되었습니다."


# ---------------- 퀴즈 관련 유틸 ----------------
def init_quiz_state():
    st.session_state["quiz_in_progress"] = False
    st.session_state["current_question"] = None
    st.session_state["current_session_id"] = None
    st.session_state["quiz_score"] = 0
    st.session_state["quiz_correct_count"] = 0
    st.session_state["quiz_total_count"] = 0
    st.session_state["quiz_area_stats"] = {}
    st.session_state["quiz_start_time"] = None
    st.session_state["current_question_start"] = None


def start_new_session():
    init_quiz_state()
    st.session_state["quiz_in_progress"] = True
    st.session_state["quiz_start_time"] = datetime.datetime.now()
    st.session_state["current_session_id"] = (
        f"{st.session_state['username']}_"
        f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    )


def select_next_question(df_q, username):
    if df_q.empty:
        return None

    df_log = load_quiz_log()
    user_log = df_log[df_log["username"] == username]

    all_ids = df_q["문항ID"].tolist()
    if not user_log.empty:
        last_status = user_log.sort_values("응시일").groupby("문항ID")["정답여부"].last()
    else:
        last_status = pd.Series(dtype=float)

    unseen_ids = [qid for qid in all_ids if qid not in last_status.index]
    wrong_ids = [qid for qid, correct in last_status.items() if correct == 0]
    candidate_ids = list(set(unseen_ids + wrong_ids))
    if not candidate_ids:
        candidate_ids = all_ids

    df_candidates = df_q[df_q["문항ID"].isin(candidate_ids)].copy()

    weights = []
    for _, row in df_candidates.iterrows():
        area = str(row["영역"])
        base_w = 2 if area in HIGH_FREQ_AREAS else 1
        weights.append(base_w)

    total_w = sum(weights)
    if total_w == 0:
        idx = random.choice(df_candidates.index.tolist())
    else:
        r = random.uniform(0, total_w)
        cum = 0
        chosen_idx = df_candidates.index[0]
        for w, idx_ in zip(weights, df_candidates.index):
            cum += w
            if r <= cum:
                chosen_idx = idx_
                break
        idx = chosen_idx

    return df_candidates.loc[idx]


def update_area_stats(area, correct):
    stats = st.session_state.get("quiz_area_stats", {})
    if area not in stats:
        stats[area] = {"total": 0, "correct": 0}
    stats[area]["total"] += 1
    if correct:
        stats[area]["correct"] += 1
    st.session_state["quiz_area_stats"] = stats


def record_question_result(username, question_row, correct, elapsed_sec):
    df_log = load_quiz_log()
    diff = str(question_row["난도"])
    area = str(question_row["영역"])
    점수 = DIFFICULTY_SCORE.get(diff, 1) if correct else 0

    new_row = {
        "username": username,
        "session_id": st.session_state.get("current_session_id"),
        "문항ID": question_row["문항ID"],
        "정답여부": 1 if correct else 0,
        "난도": diff,
        "영역": area,
        "득점": 점수,
        "풀이시간초": elapsed_sec,
        "응시일": datetime.datetime.now().isoformat()
    }
    df_log = pd.concat([df_log, pd.DataFrame([new_row])], ignore_index=True)
    save_quiz_log(df_log)


def finalize_session(username):
    if not st.session_state.get("current_session_id"):
        return
    df_log = load_quiz_log()
    sid = st.session_state["current_session_id"]
    sess_logs = df_log[df_log["session_id"] == sid]
    if sess_logs.empty:
        return

    총점 = sess_logs["득점"].sum()
    총문항수 = len(sess_logs)
    정답수 = sess_logs["정답여부"].sum()
    정답률 = (정답수 / 총문항수) * 100 if 총문항수 > 0 else 0

    시작시각 = st.session_state.get("quiz_start_time", datetime.datetime.now())
    종료시각 = datetime.datetime.now()
    총풀이시간초 = (종료시각 - 시작시각).total_seconds()

    df_sess = load_quiz_sessions()
    new_row = {
        "username": username,
        "session_id": sid,
        "총점": 총점,
        "총문항수": 총문항수,
        "정답수": 정답수,
        "정답률": 정답률,
        "총풀이시간초": 총풀이시간초,
        "시작시각": 시작시각.isoformat(),
        "종료시각": 종료시각.isoformat()
    }
    df_sess = pd.concat([df_sess, pd.DataFrame([new_row])], ignore_index=True)
    save_quiz_sessions(df_sess)


def get_high_achiever_avg_time():
    df_sess = load_quiz_sessions()
    if df_sess.empty:
        return None
    cond = (df_sess["총점"] >= 80) & (df_sess["정답률"] >= 80)
    df_good = df_sess[cond]
    if df_good.empty:
        return None
    df_good = df_good[df_good["총문항수"] > 0]
    if df_good.empty:
        return None
    per_q = df_good["총풀이시간초"] / df_good["총문항수"]
    return per_q.mean()


# ---------------- 세션 상태 초기화 ----------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = None
if "name" not in st.session_state:
    st.session_state["name"] = None
if "is_admin_menu" not in st.session_state:
    st.session_state["is_admin_menu"] = False

if "quiz_in_progress" not in st.session_state:
    init_quiz_state()


# ---------------- 사이드바: 로그인 / 회원가입 / 관리자 ----------------
with st.sidebar:
    st.header("회원 / 관리자")

    if not st.session_state["logged_in"]:
        tab_login, tab_register, tab_admin = st.tabs(["로그인", "회원가입", "관리자 메뉴"])

        with tab_login:
            st.subheader("학생 로그인")
            login_id = st.text_input("아이디", key="login_id")
            login_pw = st.text_input("비밀번호", type="password", key="login_pw")
            if st.button("로그인"):
                user = authenticate_user(login_id, login_pw)
                if user is None:
                    st.error("아이디 또는 비밀번호가 올바르지 않습니다.")
                else:
                    st.session_state["logged_in"] = True
                    st.session_state["username"] = user["username"]
                    st.session_state["name"] = user["name"]
                    st.success(f"{user['name']}님, 환영합니다!")
                    init_quiz_state()

        with tab_register:
            st.subheader("학생 회원가입")
            new_username = st.text_input("아이디 (로그인에 사용할 이름)")
            new_password = st.text_input("비밀번호", type="password")
            new_password2 = st.text_input("비밀번호 확인", type="password")
            new_student_id = st.text_input("학번 (예: 2111)")
            new_name = st.text_input("성명")
            new_email = st.text_input("이메일")

            if st.button("회원가입"):
                if new_password != new_password2:
                    st.error("비밀번호가 일치하지 않습니다.")
                elif not (new_username and new_password and new_student_id and new_name):
                    st.error("필수 항목(아이디, 비밀번호, 학번, 성명)을 모두 입력해 주세요.")
                else:
                    ok, msg = register_user(
                        new_username, new_password,
                        new_student_id, new_name, new_email
                    )
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)

        with tab_admin:
            st.subheader("관리자 메뉴 접속")
            admin_pw_input = st.text_input("관리자 비밀번호", type="password")
            if st.button("관리자 메뉴 열기"):
                if admin_pw_input == ADMIN_MENU_PASSWORD:
                    st.session_state["is_admin_menu"] = True
                    st.success("관리자 메뉴에 접속했습니다.")
                else:
                    st.session_state["is_admin_menu"] = False
                    st.error("관리자 비밀번호가 올바르지 않습니다.")

    else:
        st.markdown(f"**로그인 중:** {st.session_state['name']} ({st.session_state['username']})")
        if st.button("로그아웃"):
            st.session_state["logged_in"] = False
            st.session_state["username"] = None
            st.session_state["name"] = None
            init_quiz_state()
            st.session_state["is_admin_menu"] = False
            st.success("로그아웃되었습니다.")


# ---------------- 메인 영역 ----------------
questions_df = load_questions()

if st.session_state["is_admin_menu"]:
    st.markdown("---")
    st.subheader("관리자 메뉴")

    admin_tab1, admin_tab2 = st.tabs(["회원 관리", "퀴즈 도전 이력 요약"])

    with admin_tab1:
        st.markdown("### 회원 목록")
        users_df = load_users()
        st.dataframe(users_df)

        st.markdown("#### 회원 비밀번호 변경")
        target_user = st.text_input("비밀번호를 변경할 아이디")
        new_pw_admin = st.text_input("새 비밀번호", type="password")
        if st.button("비밀번호 변경 실행"):
            ok, msg = change_user_password(target_user, new_pw_admin)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

        st.markdown("#### 회원 정보 삭제")
        del_user = st.text_input("삭제할 아이디")
        if st.button("회원 삭제 실행"):
            ok, msg = delete_user(del_user)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

    with admin_tab2:
        st.markdown("### 퀴즈 도전 이력 요약")
        quiz_log_df = load_quiz_log()
        sess_df = load_quiz_sessions()
        st.markdown("#### 회차별 성적 요약")
        if sess_df.empty:
            st.info("아직 저장된 퀴즈 세션 기록이 없습니다.")
        else:
            st.dataframe(sess_df)

        st.markdown("#### 문항별 풀이 기록")
        if quiz_log_df.empty:
            st.info("아직 문항 풀이 기록이 없습니다.")
        else:
            st.dataframe(quiz_log_df)

if not st.session_state["logged_in"]:
    st.markdown("---")
    st.info("좌측 사이드바에서 **로그인 또는 회원가입**을 먼저 진행해 주세요.")
else:
    st.markdown("---")
    menu = st.radio(
        "메뉴 선택",
        ["퀴즈 도전", "오답노트", "내 성취 분석"],
        horizontal=True
    )

    username = st.session_state["username"]

    if menu == "퀴즈 도전":
        if questions_df.empty:
            st.error("문제 데이터가 없습니다. 관리자에게 문의해 주세요.")
        else:
            if not st.session_state["quiz_in_progress"]:
                st.markdown("### 국어 문법 퀴즈 도전")
                st.write("버튼을 눌러 새 회차 퀴즈를 시작하세요.")
                if st.button("퀴즈 도전 시작"):
                    start_new_session()
                    st.rerun()
            else:
                st.markdown("### 국어 문법 퀴즈 진행 중")

                col_left, col_right = st.columns([1, 2])

                with col_left:
                    start_time = st.session_state.get("quiz_start_time", datetime.datetime.now())
                    elapsed = datetime.datetime.now() - start_time
                    total_sec = int(elapsed.total_seconds())
                    mm = total_sec // 60
                    ss = total_sec % 60
                    st.markdown(f"**⏱ 경과 시간:** {mm:02d}분 {ss:02d}초")

                    avg_time = get_high_achiever_avg_time()
                    if avg_time is not None:
                        st.caption(f"우수 성취 학생(80점·정답률 80% 이상)의 평균 문제 해결 시간: 약 {avg_time:.1f}초/문항")
                    else:
                        st.caption("우수 성취 학생 데이터가 아직 부족합니다.")

                with col_right:
                    score = st.session_state["quiz_score"]
                    total = st.session_state["quiz_total_count"]
                    correct = st.session_state["quiz_correct_count"]
                    acc = (correct / total * 100) if total > 0 else 0
                    st.markdown(f"**현재 점수:** {score}점")
                    st.markdown(f"**푼 문제 수:** {total}문항 / 맞힌 문제: {correct}문항")
                    st.markdown(f"**정답률:** {acc:.1f}%")

                    area_stats = st.session_state.get("quiz_area_stats", {})
                    if area_stats:
                        rows = []
                        for area, stat in area_stats.items():
                            t = stat["total"]
                            c = stat["correct"]
                            a = (c / t * 100) if t > 0 else 0
                            rows.append({"영역": area, "푼 문항수": t, "맞힌 문항수": c, "정답률(%)": round(a, 1)})
                        df_area = pd.DataFrame(rows)
                        st.dataframe(df_area, use_container_width=True)

                st.markdown("---")

                if st.session_state["current_question"] is None:
                    q_row = select_next_question(questions_df, username)
                    if q_row is None:
                        st.info("더 이상 출제할 문제가 없습니다. 잠시 후 다시 시도해 주세요.")
                        st.session_state["quiz_in_progress"] = False
                    else:
                        st.session_state["current_question"] = q_row.to_dict()
                        st.session_state["current_question_start"] = datetime.datetime.now()
                        st.rerun()

                if st.session_state["current_question"] is not None:
                    q = st.session_state["current_question"]
                    st.markdown(f"**문항ID:** {q['문항ID']} | **영역:** {q['영역']} | **난도:** {q['난도']}")
                    st.write("")
                    st.markdown(f"#### 문제\n{q['문제']}")

                    options = [q["선지1"], q["선지2"], q["선지3"], q["선지4"]]
                    user_choice = st.radio(
                        "정답을 고르세요.",
                        options=list(range(1, 5)),
                        format_func=lambda x: f"{x}. {options[x-1]}",
                        key="current_choice"
                    )

                    col_btn1, col_btn2, col_btn3 = st.columns(3)
                    result_placeholder = st.empty()
                    explanation_placeholder = st.empty()

                    with col_btn1:
                        if st.button("정답 제출"):
                            correct_answer = int(q["정답"])
                            is_correct = (user_choice == correct_answer)
                            now = datetime.datetime.now()
                            q_start = st.session_state.get("current_question_start", now)
                            elapsed_q = (now - q_start).total_seconds()

                            record_question_result(username, q, is_correct, elapsed_q)
                            update_area_stats(q["영역"], is_correct)
                            st.session_state["quiz_total_count"] += 1
                            if is_correct:
                                st.session_state["quiz_correct_count"] += 1
                                st.session_state["quiz_score"] += DIFFICULTY_SCORE.get(str(q["난도"]), 1)

                            if is_correct:
                                result_placeholder.success("정답입니다! 👏")
                                show_explain = st.button("찍었으면 풀이 확인")
                                next_btn = st.button("확실히 이해하고 풀었어요 다음문제로")
                                if show_explain:
                                    explanation_placeholder.info(f"해설:\n\n{q['해설']}")
                                if next_btn:
                                    st.session_state["current_question"] = None
                                    st.session_state["current_question_start"] = None
                                    st.rerun()
                            else:
                                result_placeholder.error("틀렸습니다. 정답과 해설을 확인하세요.")
                                explanation_placeholder.info(
                                    f"정답: {q['정답']}번 - {options[int(q['정답'])-1]}\n\n해설:\n\n{q['해설']}"
                                )
                                if st.button("다음 문제로"):
                                    st.session_state["current_question"] = None
                                    st.session_state["current_question_start"] = None
                                    st.rerun()

                            if st.session_state["quiz_score"] >= 100:
                                finalize_session(username)
                                st.session_state["quiz_in_progress"] = False
                                st.session_state["current_question"] = None
                                st.session_state["current_question_start"] = None
                                st.success("100점을 달성했습니다. 수고했습니다. 다음 회차에 도전하세요.")

                    with col_btn2:
                        if st.button("모르겠어요 (정답 보기)"):
                            now = datetime.datetime.now()
                            q_start = st.session_state.get("current_question_start", now)
                            elapsed_q = (now - q_start).total_seconds()
                            record_question_result(username, q, False, elapsed_q)
                            update_area_stats(q["영역"], False)
                            st.session_state["quiz_total_count"] += 1

                            result_placeholder.warning("모르겠다고 선택했습니다. 정답과 해설을 확인하세요.")
                            explanation_placeholder.info(
                                f"정답: {q['정답']}번 - {options[int(q['정답'])-1]}\n\n해설:\n\n{q['해설']}"
                            )
                            if st.button("다음 문제로 이동"):
                                st.session_state["current_question"] = None
                                st.session_state["current_question_start"] = None
                                st.rerun()

                    with col_btn3:
                        if st.button("그만 풀게요"):
                            finalize_session(username)
                            st.session_state["quiz_in_progress"] = False
                            st.session_state["current_question"] = None
                            st.session_state["current_question_start"] = None

                            score = st.session_state["quiz_score"]
                            total = st.session_state["quiz_total_count"]
                            correct = st.session_state["quiz_correct_count"]
                            acc = (correct / total * 100) if total > 0 else 0

                            st.info("수고했습니다. 다음 회차에 도전하세요.")
                            if score >= 80 and acc >= 80:
                                st.success("축하합니다 우수 성취학생으로 선정합니다. "
                                           "박호종 선생님에게 뛰어가 간식을 사달라 하세요!")

    elif menu == "오답노트":
        st.subheader("오답노트 & 전체 통계")
        df_log = load_quiz_log()
        if df_log.empty:
            st.info("아직 푼 문제가 없어 오답노트가 없습니다.")
        else:
            user_log = df_log[df_log["username"] == username]
            if user_log.empty:
                st.info("아직 푼 문제가 없어 오답노트가 없습니다.")
            else:
                wrong_ids = user_log[user_log["정답여부"] == 0]["문항ID"].unique()
                st.markdown(f"**내가 틀린 문제 수:** {len(wrong_ids)}문항")

                if len(wrong_ids) > 0:
                    wrong_questions = questions_df[questions_df["문항ID"].isin(wrong_ids)]
                    for _, row in wrong_questions.iterrows():
                        st.markdown("---")
                        st.markdown(f"**문항ID:** {row['문항ID']} | **영역:** {row['영역']} | **난도:** {row['난도']}")
                        st.markdown(f"문제: {row['문제']}")
                        st.markdown(f"- 1) {row['선지1']}")
                        st.markdown(f"- 2) {row['선지2']}")
                        st.markdown(f"- 3) {row['선지3']}")
                        st.markdown(f"- 4) {row['선지4']}")
                        st.info(f"정답: {row['정답']}번 | 해설: {row['해설']}")

                st.markdown("---")
                st.markdown("### 전체 학생 통계 (누적)")

                total_q = len(df_log)
                total_correct = df_log["정답여부"].sum()
                total_acc = (total_correct / total_q * 100) if total_q > 0 else 0
                st.markdown(f"- 전체 학생 누적 정답률: **{total_acc:.1f}%**")

                df_sess = load_quiz_sessions()
                if not df_sess.empty:
                    good = df_sess[(df_sess["총점"] >= 80) & (df_sess["정답률"] >= 80)]
                    if not good.empty:
                        avg_good_acc = good["정답률"].mean()
                        st.markdown(f"- 우수 성취 학생 평균 정답률: **{avg_good_acc:.1f}%**")
                    else:
                        st.markdown("- 우수 성취 학생 데이터가 아직 부족합니다.")
                else:
                    st.markdown("- 아직 회차별 성취 데이터가 없습니다.")

                area_summary = df_log.groupby("영역").agg(
                    total=("정답여부", "count"),
                    correct=("정답여부", "sum")
                )
                area_summary["정답률(%)"] = area_summary["correct"] / area_summary["total"] * 100
                area_summary["오답률(%)"] = 100 - area_summary["정답률(%)"]
                st.markdown("#### 영역별 오답률 상위 영역")
                st.dataframe(area_summary.sort_values("오답률(%)", ascending=False))

    elif menu == "내 성취 분석":
        st.subheader("내 성취 분석")
        df_log = load_quiz_log()
        df_sess = load_quiz_sessions()

        user_log = df_log[df_log["username"] == username]
        user_sess = df_sess[df_sess["username"] == username]

        if user_log.empty and user_sess.empty:
            st.info("아직 푼 문제가 없어 성취 분석을 할 수 없습니다. 먼저 퀴즈에 도전해 보세요.")
        else:
            if not user_sess.empty:
                st.markdown("### 회차별 성적")
                st.dataframe(user_sess)

            if not user_log.empty:
                st.markdown("### 영역별 강점/취약 영역")
                area_stat = user_log.groupby("영역").agg(
                    total=("정답여부", "count"),
                    correct=("정답여부", "sum")
                )
                area_stat["정답률(%)"] = area_stat["correct"] / area_stat["total"] * 100
                st.dataframe(area_stat.sort_values("정답률(%)", ascending=False))

# ---------------- 화면 좌측 하단 '제작자' 표시 ----------------
st.markdown(
    """
    <div style="position: fixed; bottom: 10px; left: 260px;
                font-size: 0.9rem; color: gray; background-color: rgba(255,255,255,0.7);
                padding: 4px 8px; border-radius: 4px; z-index: 9999;">
        제작자 함창고 국어교사 박호종
    </div>
    """,
    unsafe_allow_html=True,
)
