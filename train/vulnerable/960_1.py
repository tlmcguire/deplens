from django.contrib.auth.mixins import LoginRequiredMixin
from nautobot.extras.views import JobView

class JobButtonView(LoginRequiredMixin, JobView):
    def post(self, request, *args, **kwargs):
        if request.user.has_perm('extras.run_job'):
            return self.run_job()
        else:
            return self.permission_denied()