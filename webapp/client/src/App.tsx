import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import ScanCreate from "./pages/ScanCreate";
import ScanResults from "./pages/ScanResults";
import ScanHistory from "./pages/ScanHistory";
import AuditLog from "./pages/AuditLog";
import Settings from "./pages/Settings";
import NseScripts from "./pages/NseScripts";
import NmapReference from "./pages/NmapReference";
import LiveScan from "./pages/LiveScan";
import HostDetail from "./pages/HostDetail";
import NetworkTopology from "./pages/NetworkTopology";
import CidrManager from "./pages/CidrManager";
import CveLookup from "./pages/CveLookup";
import Alerts from "./pages/Alerts";
import DashboardLayout from "./components/DashboardLayout";
function Router() {
  // make sure to consider if you need authentication for certain routes
  return (
    <DashboardLayout>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/scan/new" component={ScanCreate} />
        <Route path="/scan/live" component={LiveScan} />
        <Route path="/scan/results" component={ScanResults} />
        <Route path="/scan/results/:id" component={ScanResults} />
        <Route path="/history" component={ScanHistory} />
        <Route path="/host/detail" component={HostDetail} />
        <Route path="/host/:id" component={HostDetail} />
        <Route path="/tools/nse" component={NseScripts} />
        <Route path="/tools/reference" component={NmapReference} />
        <Route path="/tools/topology" component={NetworkTopology} />
        <Route path="/tools/cidr" component={CidrManager} />
        <Route path="/tools/cve" component={CveLookup} />
        <Route path="/alerts" component={Alerts} />
        <Route path="/audit" component={AuditLog} />
        <Route path="/settings" component={Settings} />
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </DashboardLayout>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
