async function checkAuth(req, res) {
  try {
    // Force session reload from store
    await req.session.reload();
    
    if (!req.session.userId || req.sessionID !== req.cookies.qr_attendance_sid) {
      await req.session.destroy();
      return res.json({ authenticated: false });
    }
    
    return res.json({
      authenticated: true,
      user: req.session.user
    });
  } catch (error) {
    await req.session.destroy();
    res.json({ authenticated: false });
  }
}