async function checkAuth(req, res) {
  try {
    // Add session cleanup
    if (req.session && req.session.userId) {
      await req.session.reload();
    }
    
    if (req.session?.user) {
      res.json({ authenticated: true, user: req.session.user });
    } else {
      // Destroy any stale session
      await new Promise((resolve) => req.session.destroy(resolve));
      res.json({ authenticated: false });
    }
  } catch (error) {
    console.error("Auth check error:", error);
    res.status(500).json({ error: "Authentication check failed" });
  }
}