// 共用登入邏輯：匿名登入 + 可選的 Google 綁定
import { GoogleAuthProvider, signInAnonymously, signInWithPopup, signInWithRedirect,
         linkWithPopup, linkWithRedirect, signInWithCredential }
  from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { collection, getDocs, doc, setDoc }
  from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

let anonFailed = false;

// 沒有登入時自動匿名登入；Firebase 尚未開啟匿名登入時安靜失敗，網站照舊可用
export async function ensureAnonymous(auth) {
  if (auth.currentUser || anonFailed) return;
  try { await signInAnonymously(auth); }
  catch (e) { anonFailed = true; console.warn('匿名登入未啟用：', e.code || e.message); }
}

// Google 登入：
// - 目前是匿名身分 → 直接升級成 Google 帳號（同一個 uid，收藏留言都保留）
// - 這個 Google 帳號以前就登入過 → 改登入該帳號，並把匿名期間的收藏合併過去
export async function googleLogin(auth, db) {
  const provider = new GoogleAuthProvider();
  const cur = auth.currentUser;
  try {
    if (cur?.isAnonymous) {
      try { await linkWithPopup(cur, provider); return; }
      catch (e) {
        if (e.code !== 'auth/credential-already-in-use') throw e;
        const cred = GoogleAuthProvider.credentialFromError(e);
        const favs = await getDocs(collection(db, 'users', cur.uid, 'favorites'));
        const res = await signInWithCredential(auth, cred);
        await Promise.all(favs.docs.map(d =>
          setDoc(doc(db, 'users', res.user.uid, 'favorites', d.id), d.data())));
        return;
      }
    }
    await signInWithPopup(auth, provider);
  } catch (e) {
    if (e.code === 'auth/popup-blocked') {
      if (cur?.isAnonymous) await linkWithRedirect(cur, provider);
      else await signInWithRedirect(auth, provider);
      return;
    }
    if (e.code === 'auth/popup-closed-by-user' || e.code === 'auth/cancelled-popup-request') return;
    console.error('Google 登入失敗：', e);
    alert('登入失敗：' + (e.code || e.message));
  }
}

export const isRealUser = u => !!u && !u.isAnonymous;
