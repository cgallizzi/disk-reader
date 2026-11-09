"""Tests that need no disk, no admin rights and no network. Run: python -m unittest test_planner"""
import unittest
from unittest import mock

import recomp_planner as rp


def row(game, status="Beta", console="Xbox 360", method="Static recompilation", url="https://github.com/a/b"):
    return {"game": game, "console": console, "project": game + " port", "method": method,
            "status": status, "note": "", "url": url}


def tracker_row(game="Dante&#39;s Inferno", href="/dantes-inferno-pc/"):
    td = "<td data-x>%s</td>"
    return ('<tr id="row-x" data-x><td class="r-game">%s<div class="r-alias">alias</div>'
            '<div class="r-note">A note</div></td>' % game + td % "Xbox 360" + td % "Hell&#39;s Gate"
            + '<td class="r-method">Static recompilation</td>' + td % '<span data-stage="Beta">Beta</span>'
            + td % "<time>Nov 8</time>" + td % ('<a href="%s">Project</a>' % href) + "</tr>")


def game(title="Manhunt", family="Xbox360BackwardCompatibil.PrimaryManhunt_x", released="2004-04-20T00:00:00Z",
         optimized=("ConsoleGen8",), steam=None, gog=None):
    return {"store": "X", "title": title, "pc": {"steam": steam, "gog": gog},
            "product": {"family": family, "released": released, "optimized": list(optimized)}}


class Normalize(unittest.TestCase):
    def test_marks_accents_and_spacing(self):
        self.assertEqual(rp.normalize("Brütal Legend"), "brutal legend")
        self.assertEqual(rp.normalize("STAR WARS™ - Knights of the Old Republic™"), "star wars knights of the old republic")

    def test_edition_rules(self):
        self.assertEqual(rp.normalize("Midnight Club: Los Angeles Complete"), "midnight club los angeles")
        self.assertEqual(rp.normalize("Grand Theft Auto IV (Xbox 360 version)"), "grand theft auto iv")
        self.assertEqual(rp.normalize("Mafia: Definitive Edition for XBOX One"), "mafia definitive edition")

    def test_remaster_stays_distinct_from_original(self):
        self.assertNotEqual(rp.normalize("Grand Theft Auto III – The Definitive Edition"),
                            rp.normalize("Grand Theft Auto III"))


class Tracker(unittest.TestCase):
    def test_parses_a_row(self):
        r = rp.parse_tracker(tracker_row())[0]
        self.assertEqual((r["game"], r["console"], r["project"], r["status"]),
                         ("Dante's Inferno", "Xbox 360", "Hell's Gate", "Beta"))
        self.assertEqual(r["url"], "https://portedgames.com/dantes-inferno-pc/")

    def test_changed_layout_raises_instead_of_reporting_no_projects(self):
        with self.assertRaises(ValueError):
            rp.parse_tracker("<html>new design</html>")

    def test_exact_and_related_are_separate(self):
        rows = [row("Ninja Gaiden II"), row("Ninja Gaiden 3 Razors Edge")]
        exact, related = rp.match_tracker("NINJA GAIDEN 3: Razor's Edge", rows)
        self.assertEqual([r["game"] for r in exact], ["Ninja Gaiden 3 Razors Edge"])
        self.assertEqual([r["game"] for r in related], ["Ninja Gaiden II"])

    def test_related_games_are_not_repeated(self):
        _, related = rp.match_tracker("Max Payne 2", [row("Max Payne"), row("Max Payne")])
        self.assertEqual(len(related), 1)

    def test_one_word_title_has_no_series_matches(self):
        self.assertEqual(rp.match_tracker("Quake", [row("Quake II"), row("Quake III Arena")]), ([], []))

    def test_emulator_forks_do_not_count(self):
        self.assertEqual(rp.match_tracker("Manhunt", [row("Manhunt", method="Emulator fork")]), ([], []))


class Era(unittest.TestCase):
    def test_backward_compatible_split_by_360_launch(self):
        self.assertEqual(rp.era_of(game()["product"]), "original-xbox")
        self.assertEqual(rp.era_of(game(released="2010-05-18")["product"]), "xbox-360")
        self.assertEqual(rp.era_of(game(released="")["product"]), "backward-compatible")
        self.assertEqual(rp.era_of(game(released="2005-10-03")["product"]), "backward-compatible")

    def test_modern_packages(self):
        self.assertEqual(rp.era_of(game(family="GSC.Stalker", optimized=["ConsoleGen9"])["product"]), "series")
        self.assertEqual(rp.era_of(game(family="Rockstar.X", optimized=["ConsoleGen8"])["product"]), "xbox-one")
        self.assertEqual(rp.era_of({"family": "", "optimized": []}), "unknown")


class Classify(unittest.TestCase):
    def tier(self, g, rows):
        return rp.classify(g, rows)["tier"]

    def test_playable_project_wins(self):
        self.assertEqual(self.tier(game(steam=["Manhunt"]), [row("Manhunt", status="Working")]), "project-playable")

    def test_early_or_offline_project(self):
        self.assertEqual(self.tier(game(), [row("Manhunt", status="Early")]), "project-early")
        self.assertEqual(self.tier(game(), [row("Manhunt", status="Offline")]), "project-early")

    def test_older_game_with_and_without_pc_release(self):
        self.assertEqual(self.tier(game(steam=["Manhunt"]), []), "candidate-pc")
        self.assertEqual(self.tier(game(gog=["Manhunt"]), []), "candidate-pc")
        self.assertEqual(self.tier(game(steam=[], gog=[]), []), "candidate-console")

    def test_modern_package_is_not_a_target(self):
        self.assertEqual(self.tier(game(family="GSC.Stalker", optimized=["ConsoleGen9"], steam=["x"]), []), "modern")

    def test_unreadable_tracker_still_classifies(self):
        self.assertEqual(self.tier(game(), None), "candidate-console")


class PcLookups(unittest.TestCase):
    def setUp(self):
        self.lookups = rp.Lookups("unused", refresh=True)

    def test_store_that_cannot_find_the_probe_title_reads_as_not_checked(self):
        with mock.patch.object(rp, "fetch_json", return_value={"items": []}):
            self.assertIsNone(self.lookups.steam("Manhunt"))
        self.assertNotIn("Manhunt", self.lookups.data["steam"])

    def test_broken_store_ignores_old_cached_answers(self):
        self.lookups.data["steam"]["Manhunt"] = []
        with mock.patch.object(rp, "fetch_json", side_effect=OSError):
            self.assertIsNone(self.lookups.steam("Manhunt"))

    def test_real_no_match_is_an_empty_list_and_searches_a_simple_term(self):
        seen = []

        def reply(url):
            seen.append(url)
            return {"items": [{"name": "Quake"}]}
        with mock.patch.object(rp, "fetch_json", side_effect=reply):
            self.assertEqual(self.lookups.steam("Mafia: Definitive Edition for XBOX One"), [])
        self.assertIn("mafia%20definitive%20edition", seen[-1])

    def test_failed_search_is_not_cached_and_reads_as_not_checked(self):
        with mock.patch.object(rp, "fetch_json", side_effect=OSError):
            self.assertIsNone(self.lookups.steam("Manhunt"))
        self.assertNotIn("Manhunt", self.lookups.data["steam"])
        self.assertEqual(rp.pc_text({"steam": None, "gog": []}), "Steam: not checked, GOG: no title match")

    def test_only_close_names_count(self):
        reply = {"items": [{"name": "Cyber Manhunt"}, {"name": "Manhunt"}, {"name": "Quake"}]}
        with mock.patch.object(rp, "fetch_json", return_value=reply):
            self.assertEqual(self.lookups.steam("Manhunt"), ["Manhunt"])
        reply = {"items": [{"name": "Grand Theft Auto IV: The Complete Edition"}, {"name": "Quake"}]}
        with mock.patch.object(rp, "fetch_json", return_value=reply):
            self.assertEqual(len(self.lookups.steam("Grand Theft Auto IV")), 1)

    def test_tracker_failure_uses_older_copy(self):
        self.lookups.data["tracker"] = {"rows": [row("Old")], "at": 1}
        with mock.patch.object(rp, "fetch", side_effect=OSError):
            rows, at = self.lookups.tracker()
        self.assertEqual((rows[0]["game"], at), ("Old", 1))


class Render(unittest.TestCase):
    def plan(self, **overrides):
        r = row("<script>alert(1)</script>", **overrides)
        g = game(title="Manhunt")
        rp.classify(g, [row("Manhunt", **overrides)])
        g["exact"][0].update(project=r["game"], repo=None)
        return {"games": [g], "tracker_ok": True, "tracker_rows": 1, "tracker_at": 1000000}

    def test_tracker_text_is_escaped(self):
        page = rp.render(self.plan(), "test")
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)

    def test_only_web_links_are_rendered(self):
        self.assertNotIn("javascript:", rp.render(self.plan(url="javascript:alert(1)"), "test"))

    def test_unread_tracker_is_stated(self):
        plan = {"games": [rp.classify(game(), None)], "tracker_ok": False, "tracker_rows": 0, "tracker_at": None}
        self.assertIn("could not be read", rp.render(plan, "test"))


if __name__ == "__main__":
    unittest.main()
